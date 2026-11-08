import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

open class BuildFrontendTask : DefaultTask() {
    @Input
    var frontendDir: String? = null

    @TaskAction
    fun buildFrontend() {
        val frontendDir = frontendDir
            ?: throw GradleException("frontendDir cannot be null")
        val workingDir = File(frontendDir).canonicalFile
        if (!workingDir.isDirectory) {
            throw GradleException("Frontend directory does not exist: $workingDir")
        }

        val executable: String
        val arguments: List<String>
        if (Os.isFamily(Os.FAMILY_WINDOWS)) {
            executable = "cmd"
            arguments = listOf("/d", "/s", "/c", "npm run build")
        } else {
            executable = "npm"
            arguments = listOf("run", "build")
        }

        project.exec {
            workingDir(workingDir)
            executable(executable)
            args(arguments)
            if (project.logger.isEnabled(LogLevel.DEBUG)) {
                environment("RUST_LOG", "debug")
            }
        }.assertNormalExitValue()
    }
}

open class BuildTask : DefaultTask() {
    @Input
    var rootDirRel: String? = null
    @Input
    var target: String? = null
    @Input
    var release: Boolean? = null
    @Input
    var libName: String? = null
    @Input
    var minSdk: Int = 24
    @Input
    var ndkVersion: String? = null

    private data class TargetInfo(
        val cargoTarget: String,
        val abi: String,
        val clangPrefix: String,
        val tauriArch: String,
    )

    @TaskAction
    fun assemble() {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")
        val libName = libName ?: throw GradleException("libName cannot be null")

        val srcTauriDir = File(project.projectDir, rootDirRel).canonicalFile
        val workspaceDir = srcTauriDir.parentFile.parentFile
        val targetInfo = resolveTarget(target)
        val ndkDir = resolveNdkDir()
        val toolchainBin = resolveNdkToolchainBin(ndkDir)
        val executableSuffix = if (Os.isFamily(Os.FAMILY_WINDOWS)) ".cmd" else ""
        val archiveSuffix = if (Os.isFamily(Os.FAMILY_WINDOWS)) ".exe" else ""
        val clang = File(
            toolchainBin,
            "${targetInfo.clangPrefix}${minSdk}-clang$executableSuffix",
        )
        val archiver = File(toolchainBin, "llvm-ar$archiveSuffix")
        val strip = File(toolchainBin, "llvm-strip$archiveSuffix")
        if (!clang.isFile) {
            throw GradleException("Android NDK compiler not found: $clang")
        }
        if (!archiver.isFile) {
            throw GradleException("Android NDK archiver not found: $archiver")
        }
        if (!strip.isFile) {
            throw GradleException("Android NDK strip tool not found: $strip")
        }

        val targetDir = File(workspaceDir, "target")
        val cargoArgs = mutableListOf(
            "build",
            "--package",
            "rama-proxy-mobile",
            "--target",
            targetInfo.cargoTarget,
            "--target-dir",
            targetDir.absolutePath,
            "--features",
            "custom-protocol",
        )
        if (release) {
            cargoArgs.add("--release")
        }

        val cargo = System.getenv("CARGO")?.takeIf { it.isNotBlank() } ?: "cargo"
        val targetEnvSuffix = targetInfo.cargoTarget.replace('-', '_')
        val targetLinkerEnv =
            "CARGO_TARGET_${targetInfo.cargoTarget.uppercase().replace('-', '_')}_LINKER"

        project.exec {
            workingDir(srcTauriDir)
            executable(cargo)
            args(cargoArgs)
            environment("CC_$targetEnvSuffix", clang.absolutePath)
            environment("AR_$targetEnvSuffix", archiver.absolutePath)
            environment(targetLinkerEnv, clang.absolutePath)
            environment(
                "CARGO_TARGET_${targetInfo.cargoTarget.uppercase().replace('-', '_')}_RUSTFLAGS",
                "-Clink-arg=-landroid -Clink-arg=-llog -Clink-arg=-lOpenSLES -Clink-arg=-Wl,-z,max-page-size=16384 -Clink-arg=-Wl,-z,common-page-size=16384",
            )
            environment("TAURI_ENV_TARGET_TRIPLE", targetInfo.cargoTarget)
            environment("TAURI_ENV_PLATFORM", "android")
            environment("TAURI_ENV_FAMILY", "unix")
            environment("TAURI_ENV_ARCH", targetInfo.tauriArch)
            // Gradle builds always embed the production frontend. Only `tauri dev`
            // should point the Android WebView at the Vite dev server.
            environment("TAURI_ENV_DEBUG", "false")
            environment("TAURI_ANDROID_PACKAGE_NAME_APP_NAME", "ramaproxy")
            environment("TAURI_ANDROID_PACKAGE_NAME_PREFIX", "com_zqliang")
            if (project.logger.isEnabled(LogLevel.DEBUG)) {
                environment("RUST_LOG", "debug")
            }
        }.assertNormalExitValue()

        val profile = if (release) "release" else "debug"
        val source = File(
            targetDir,
            "${targetInfo.cargoTarget}/$profile/$libName.so",
        )
        if (!source.isFile) {
            throw GradleException("Rust shared library was not produced: $source")
        }

        val destinationDir = File(
            srcTauriDir,
            "gen/android/app/src/main/jniLibs/${targetInfo.abi}",
        ).canonicalFile
        destinationDir.mkdirs()
        val destination = File(destinationDir, "$libName.so")
        if (Files.isSymbolicLink(destination.toPath())) {
            Files.delete(destination.toPath())
        }
        Files.copy(
            source.toPath(),
            destination.toPath(),
            StandardCopyOption.REPLACE_EXISTING,
        )
        project.exec {
            workingDir(srcTauriDir)
            executable(strip.absolutePath)
            args("--strip-unneeded", destination.absolutePath)
        }.assertNormalExitValue()
        logger.lifecycle("Copied and stripped $source to $destination")
    }

    private fun resolveTarget(target: String): TargetInfo = when (target) {
        "aarch64" -> TargetInfo(
            "aarch64-linux-android",
            "arm64-v8a",
            "aarch64-linux-android",
            "aarch64",
        )
        "armv7" -> TargetInfo(
            "armv7-linux-androideabi",
            "armeabi-v7a",
            "armv7a-linux-androideabi",
            "armv7",
        )
        "i686" -> TargetInfo(
            "i686-linux-android",
            "x86",
            "i686-linux-android",
            "i686",
        )
        "x86_64" -> TargetInfo(
            "x86_64-linux-android",
            "x86_64",
            "x86_64-linux-android",
            "x86_64",
        )
        else -> throw GradleException("Unsupported Android Rust target: $target")
    }

    private fun resolveNdkDir(): File {
        val explicitCandidates = listOf(
            System.getenv("ANDROID_NDK_HOME"),
            System.getenv("ANDROID_NDK_ROOT"),
            System.getenv("NDK_HOME"),
        )
        for (candidate in explicitCandidates) {
            if (!candidate.isNullOrBlank() && File(candidate).isDirectory) {
                return File(candidate).canonicalFile
            }
        }

        val localProperties = readLocalProperties()
        localProperties.getProperty("ndk.dir")?.takeIf { it.isNotBlank() }?.let {
            val ndkDir = File(it)
            if (ndkDir.isDirectory) {
                return ndkDir.canonicalFile
            }
        }

        val sdkCandidates = listOf(
            localProperties.getProperty("sdk.dir"),
            System.getenv("ANDROID_HOME"),
            System.getenv("ANDROID_SDK_ROOT"),
        )
        for (sdkCandidate in sdkCandidates) {
            if (sdkCandidate.isNullOrBlank()) {
                continue
            }
            val ndkRoot = File(sdkCandidate, "ndk")
            val configuredVersion = ndkVersion?.takeIf { it.isNotBlank() }
            val configuredNdk = configuredVersion?.let { File(ndkRoot, it) }
            if (configuredNdk?.isDirectory == true) {
                return configuredNdk.canonicalFile
            }
            val installedNdks = ndkRoot.listFiles()
                ?.filter { it.isDirectory }
                ?.sortedByDescending { it.name }
                .orEmpty()
            if (installedNdks.isNotEmpty()) {
                return installedNdks.first().canonicalFile
            }
        }

        throw GradleException(
            "Android NDK not found. Set ANDROID_NDK_HOME/NDK_HOME or install an NDK " +
                "under the Android SDK's ndk directory.",
        )
    }

    private fun readLocalProperties(): Properties {
        val properties = Properties()
        val localProperties = File(project.rootProject.projectDir, "local.properties")
        if (localProperties.isFile) {
            localProperties.bufferedReader(Charsets.UTF_8).use { properties.load(it) }
        }
        return properties
    }

    private fun resolveNdkToolchainBin(ndkDir: File): File {
        val prebuiltDir = File(ndkDir, "toolchains/llvm/prebuilt")
        val hostCandidates = if (Os.isFamily(Os.FAMILY_WINDOWS)) {
            listOf("windows-x86_64")
        } else if (Os.isFamily(Os.FAMILY_MAC)) {
            listOf("darwin-arm64", "darwin-x86_64")
        } else {
            listOf("linux-x86_64", "linux-aarch64")
        }
        for (host in hostCandidates) {
            val binDir = File(prebuiltDir, "$host/bin")
            if (binDir.isDirectory) {
                return binDir
            }
        }
        throw GradleException("Android NDK LLVM toolchain not found under: $prebuiltDir")
    }
}