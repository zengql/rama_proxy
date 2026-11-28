use std::sync::mpsc::Sender;

use crate::TrayCommand;

#[cfg(windows)]
mod platform {
    use std::{
        cell::RefCell,
        ffi::OsStr,
        mem,
        os::windows::ffi::OsStrExt,
        ptr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc::{self, Sender},
        },
        thread::{self, JoinHandle},
    };

    use windows_sys::Win32::{
        Foundation::{GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
                Shell_NotifyIconW,
            },
            WindowsAndMessaging::{
                CW_USEDEFAULT, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon,
                DestroyMenu, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, HICON,
                HMENU, IMAGE_ICON, InsertMenuItemW, LR_DEFAULTCOLOR, LR_DEFAULTSIZE, LoadImageW,
                MENUITEMINFOW, MFT_SEPARATOR, MFT_STRING, MIIM_FTYPE, MIIM_ID, MIIM_STRING, MSG,
                PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW,
                SetForegroundWindow, SetMenuItemInfoW, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
                TPM_LEFTBUTTON, TrackPopupMenu, TranslateMessage, WM_CLOSE, WM_COMMAND, WM_DESTROY,
                WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_USER, WNDCLASSW, WS_OVERLAPPEDWINDOW,
            },
        },
    };

    use crate::TrayCommand;

    // The Windows resource compiler preserves the quoted RC identifier.
    const DEFAULT_ICON_RESOURCE: &str = "\"rama-proxy-ladder\"";
    const TRAY_CLASS_NAME: &str = "rama_proxy_tray_window";
    const WM_TRAY_ICON: u32 = WM_USER + 1;
    const WM_UPDATE_CLIENT_STATE: u32 = WM_USER + 2;
    const MENU_ID_TOGGLE_CLIENT: u32 = 1;
    const MENU_ID_OPEN: u32 = 2;
    const MENU_ID_EXIT: u32 = 3;

    struct TrayWindowState {
        hwnd: HWND,
        hmenu: HMENU,
        hicon: HICON,
        base_title: String,
        tooltip: Vec<u16>,
        taskbar_created_msg: u32,
        sender: Sender<TrayCommand>,
        alive: Arc<AtomicBool>,
    }

    thread_local! {
        static TRAY_STATE: RefCell<Option<TrayWindowState>> = const { RefCell::new(None) };
    }

    pub(crate) struct TrayHandle {
        hwnd: HWND,
        alive: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl TrayHandle {
        pub(crate) fn new(title: &str, sender: Sender<TrayCommand>) -> Result<Self, String> {
            Self::new_with_icon_resource(title, DEFAULT_ICON_RESOURCE, sender)
        }

        pub(crate) fn new_with_icon_resource(
            title: &str,
            icon_resource: &str,
            sender: Sender<TrayCommand>,
        ) -> Result<Self, String> {
            let title = title.to_string();
            let icon_resource = icon_resource.to_string();
            let alive = Arc::new(AtomicBool::new(false));
            let thread_alive = Arc::clone(&alive);
            let (init_tx, init_rx) = mpsc::channel();

            let thread = thread::Builder::new()
                .name("rama-proxy-tray".to_string())
                .spawn(move || unsafe {
                    let state =
                        match init_tray(&title, &icon_resource, sender, thread_alive.clone()) {
                            Ok(state) => state,
                            Err(err) => {
                                let _ = init_tx.send(Err(err));
                                return;
                            }
                        };

                    let hwnd = state.hwnd;
                    TRAY_STATE.with(|slot| {
                        *slot.borrow_mut() = Some(state);
                    });
                    thread_alive.store(true, Ordering::Release);
                    let _ = init_tx.send(Ok(hwnd));

                    let mut msg = mem::zeroed::<MSG>();
                    loop {
                        let ret = GetMessageW(&mut msg, 0, 0, 0);
                        if ret <= 0 {
                            break;
                        }
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }

                    thread_alive.store(false, Ordering::Release);
                    TRAY_STATE.with(|slot| {
                        if let Some(state) = slot.borrow_mut().take() {
                            delete_notify_icon(state.hwnd);
                            DestroyMenu(state.hmenu);
                            DestroyIcon(state.hicon);
                        }
                    });
                })
                .map_err(|err| format!("failed to spawn tray thread: {err}"))?;

            match init_rx.recv() {
                Ok(Ok(hwnd)) => Ok(Self {
                    hwnd,
                    alive,
                    thread: Some(thread),
                }),
                Ok(Err(err)) => {
                    let _ = thread.join();
                    Err(err)
                }
                Err(_) => {
                    let _ = thread.join();
                    Err("tray initialization thread terminated unexpectedly".to_string())
                }
            }
        }

        pub(crate) fn is_available(&self) -> bool {
            self.alive.load(Ordering::Acquire)
        }

        pub(crate) fn set_client_running(&self, running: bool) {
            if self.is_available() {
                unsafe {
                    PostMessageW(self.hwnd, WM_UPDATE_CLIENT_STATE, usize::from(running), 0);
                }
            }
        }
    }

    impl Drop for TrayHandle {
        fn drop(&mut self) {
            self.alive.store(false, Ordering::Release);
            unsafe {
                PostMessageW(self.hwnd, WM_CLOSE, 0, 0);
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    unsafe fn init_tray(
        title: &str,
        icon_resource: &str,
        sender: Sender<TrayCommand>,
        alive: Arc<AtomicBool>,
    ) -> Result<TrayWindowState, String> {
        let base_title = title.to_string();
        let tooltip = format_tooltip(&base_title, false);

        unsafe {
            let hmodule = GetModuleHandleW(ptr::null());
            if hmodule == 0 {
                return Err(win_error("GetModuleHandleW failed"));
            }

            let class_name = to_wstring(TRAY_CLASS_NAME);
            let mut wnd = mem::zeroed::<WNDCLASSW>();
            wnd.lpfnWndProc = Some(window_proc);
            wnd.hInstance = hmodule;
            wnd.lpszClassName = class_name.as_ptr();
            RegisterClassW(&wnd);

            let window_title = to_wstring("rama_proxy_tray_hidden");
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                window_title.as_ptr(),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                0,
                CW_USEDEFAULT,
                0,
                0,
                0,
                hmodule,
                ptr::null(),
            );
            if hwnd == 0 {
                return Err(win_error("CreateWindowExW failed"));
            }

            let hicon = LoadImageW(
                hmodule,
                to_wstring(icon_resource).as_ptr(),
                IMAGE_ICON,
                0,
                0,
                LR_DEFAULTSIZE | LR_DEFAULTCOLOR,
            ) as HICON;
            if hicon == 0 {
                let err = win_error("LoadImageW failed");
                DestroyWindow(hwnd);
                return Err(err);
            }

            let hmenu = CreatePopupMenu();
            if hmenu == 0 {
                let err = win_error("CreatePopupMenu failed");
                DestroyIcon(hicon);
                DestroyWindow(hwnd);
                return Err(err);
            }

            if let Err(err) = insert_menu_item(hmenu, 0, MENU_ID_TOGGLE_CLIENT, "Start client")
                .and_then(|()| insert_separator(hmenu, 1))
                .and_then(|()| insert_menu_item(hmenu, 2, MENU_ID_OPEN, "Open"))
                .and_then(|()| insert_menu_item(hmenu, 3, MENU_ID_EXIT, "Exit"))
            {
                DestroyMenu(hmenu);
                DestroyIcon(hicon);
                DestroyWindow(hwnd);
                return Err(err);
            }

            if let Err(err) = add_notify_icon(hwnd, hicon, &tooltip) {
                DestroyMenu(hmenu);
                DestroyIcon(hicon);
                DestroyWindow(hwnd);
                return Err(err);
            }

            let taskbar_created_msg = RegisterWindowMessageW(to_wstring("TaskbarCreated").as_ptr());

            Ok(TrayWindowState {
                hwnd,
                hmenu,
                hicon,
                base_title,
                tooltip,
                taskbar_created_msg,
                sender,
                alive,
            })
        }
    }

    unsafe fn insert_menu_item(hmenu: HMENU, pos: u32, id: u32, label: &str) -> Result<(), String> {
        let mut wide = to_wstring(label);
        unsafe {
            let mut item = mem::zeroed::<MENUITEMINFOW>();
            item.cbSize = mem::size_of::<MENUITEMINFOW>() as u32;
            item.fMask = MIIM_FTYPE | MIIM_STRING | MIIM_ID;
            item.fType = MFT_STRING;
            item.wID = id;
            item.dwTypeData = wide.as_mut_ptr();
            if InsertMenuItemW(hmenu, pos, 1, &item) == 0 {
                return Err(win_error("InsertMenuItemW failed"));
            }
        }
        Ok(())
    }

    unsafe fn insert_separator(hmenu: HMENU, pos: u32) -> Result<(), String> {
        unsafe {
            let mut item = mem::zeroed::<MENUITEMINFOW>();
            item.cbSize = mem::size_of::<MENUITEMINFOW>() as u32;
            item.fMask = MIIM_FTYPE;
            item.fType = MFT_SEPARATOR;
            if InsertMenuItemW(hmenu, pos, 1, &item) == 0 {
                return Err(win_error("InsertMenuItemW(separator) failed"));
            }
        }
        Ok(())
    }

    unsafe fn set_menu_item_text(hmenu: HMENU, id: u32, label: &str) {
        let mut wide = to_wstring(label);
        unsafe {
            let mut item = mem::zeroed::<MENUITEMINFOW>();
            item.cbSize = mem::size_of::<MENUITEMINFOW>() as u32;
            item.fMask = MIIM_STRING;
            item.dwTypeData = wide.as_mut_ptr();
            let _ = SetMenuItemInfoW(hmenu, id, 0, &item);
        }
    }

    unsafe fn add_notify_icon(hwnd: HWND, hicon: HICON, tooltip: &[u16]) -> Result<(), String> {
        unsafe {
            let mut nid = mem::zeroed::<NOTIFYICONDATAW>();
            nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAY_ICON;
            nid.hIcon = hicon;
            nid.szTip[..tooltip.len()].copy_from_slice(tooltip);
            if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
                return Err(win_error("Shell_NotifyIconW(NIM_ADD) failed"));
            }
        }
        Ok(())
    }

    unsafe fn modify_notify_icon_tip(hwnd: HWND, tooltip: &[u16]) {
        unsafe {
            let mut nid = mem::zeroed::<NOTIFYICONDATAW>();
            nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_TIP;
            nid.szTip[..tooltip.len()].copy_from_slice(tooltip);
            let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    }

    unsafe fn delete_notify_icon(hwnd: HWND) {
        unsafe {
            let mut nid = mem::zeroed::<NOTIFYICONDATAW>();
            nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
        }
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        w_param: WPARAM,
        l_param: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_COMMAND => {
                let menu_id = (w_param & 0xFFFF) as u32;
                TRAY_STATE.with(|slot| {
                    if let Some(state) = slot.borrow().as_ref() {
                        match menu_id {
                            MENU_ID_TOGGLE_CLIENT => {
                                let _ = state.sender.send(TrayCommand::ToggleClient);
                            }
                            MENU_ID_OPEN => {
                                let _ = state.sender.send(TrayCommand::Show);
                            }
                            MENU_ID_EXIT => {
                                let _ = state.sender.send(TrayCommand::Quit);
                            }
                            _ => {}
                        }
                    }
                });
                0
            }
            WM_UPDATE_CLIENT_STATE => {
                let running = w_param != 0;
                TRAY_STATE.with(|slot| {
                    if let Some(state) = slot.borrow_mut().as_mut() {
                        let label = if running {
                            "Stop client"
                        } else {
                            "Start client"
                        };
                        unsafe {
                            set_menu_item_text(state.hmenu, MENU_ID_TOGGLE_CLIENT, label);
                            state.tooltip = format_tooltip(&state.base_title, running);
                            modify_notify_icon_tip(hwnd, &state.tooltip);
                        }
                    }
                });
                0
            }
            WM_TRAY_ICON if l_param as u32 == WM_LBUTTONUP || l_param as u32 == WM_RBUTTONUP => {
                let mut point = POINT { x: 0, y: 0 };
                unsafe {
                    if GetCursorPos(&mut point) != 0 {
                        SetForegroundWindow(hwnd);
                        TRAY_STATE.with(|slot| {
                            if let Some(state) = slot.borrow().as_ref() {
                                TrackPopupMenu(
                                    state.hmenu,
                                    TPM_LEFTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                                    point.x,
                                    point.y,
                                    0,
                                    hwnd,
                                    ptr::null(),
                                );
                            }
                        });
                        PostMessageW(hwnd, WM_NULL, 0, 0);
                    }
                }
                0
            }
            WM_CLOSE => {
                unsafe {
                    DestroyWindow(hwnd);
                }
                0
            }
            WM_DESTROY => {
                unsafe {
                    PostQuitMessage(0);
                }
                0
            }
            _ => {
                let taskbar_recreated_failed = TRAY_STATE.with(|slot| {
                    if let Some(state) = slot.borrow().as_ref() {
                        if state.taskbar_created_msg != 0
                            && msg == state.taskbar_created_msg
                            && unsafe { add_notify_icon(hwnd, state.hicon, &state.tooltip) }
                                .is_err()
                        {
                            state.alive.store(false, Ordering::Release);
                            return true;
                        }
                    }
                    false
                });
                unsafe {
                    if taskbar_recreated_failed {
                        DestroyWindow(hwnd);
                        return 0;
                    }
                    DefWindowProcW(hwnd, msg, w_param, l_param)
                }
            }
        }
    }

    fn format_tooltip(base_title: &str, running: bool) -> Vec<u16> {
        let status = if running { "Running" } else { "Stopped" };
        let text = format!("{base_title} ({status})");
        let mut wide: Vec<u16> = text.encode_utf16().take(127).collect();
        wide.push(0);
        wide
    }

    fn to_wstring(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    unsafe fn win_error(prefix: &str) -> String {
        format!("{prefix}: error {}", unsafe { GetLastError() })
    }
}

#[cfg(not(windows))]
mod platform {
    use std::sync::mpsc::Sender;

    use tray_item::{IconSource, TrayItem};

    use crate::TrayCommand;

    pub(crate) struct TrayHandle {
        _tray: TrayItem,
    }

    impl TrayHandle {
        pub(crate) fn new(title: &str, sender: Sender<TrayCommand>) -> Result<Self, String> {
            let mut tray = TrayItem::new(title, IconSource::Resource("\"rama-proxy-ladder\""))
                .map_err(|err| err.to_string())?;
            let toggle = sender.clone();
            tray.add_menu_item("Start / Stop client", move || {
                let _ = toggle.send(TrayCommand::ToggleClient);
            })
            .map_err(|err| err.to_string())?;
            let show = sender.clone();
            tray.add_menu_item("Open", move || {
                let _ = show.send(TrayCommand::Show);
            })
            .map_err(|err| err.to_string())?;
            tray.add_menu_item("Exit", move || {
                let _ = sender.send(TrayCommand::Quit);
            })
            .map_err(|err| err.to_string())?;
            Ok(Self { _tray: tray })
        }

        pub(crate) fn is_available(&self) -> bool {
            true
        }

        pub(crate) fn set_client_running(&self, _running: bool) {}
    }
}

pub(crate) use platform::TrayHandle;

pub(crate) fn create_tray(sender: Sender<TrayCommand>) -> Result<TrayHandle, String> {
    TrayHandle::new(crate::APP_NAME, sender)
}
