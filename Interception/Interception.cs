global using InterceptionContext = nint;
global using InterceptionDevice = int;
global using InterceptionPrecedence = int;
global using InterceptionFilter = ushort;

using System.Runtime.InteropServices;
using static Kernel32;

public unsafe static class Interception
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool Predicate(InterceptionDevice device);

    const nint INVALID_HANDLE_VALUE = -1;
    const int FILE_DEVICE_UNKNOWN = 0x22;
    const int METHOD_BUFFERED = 0;
    const int FILE_ANY_ACCESS = 0;
    const int INFINITE = unchecked((int)0xFFFFFFFF);
    const int WAIT_FAILED = unchecked((int)0xFFFFFFFF);
    const int WAIT_TIMEOUT = 258;

    const int MaxKeyboards = 10;
    const int MaxMouses = 10;
    const int MaxDevices = MaxKeyboards + MaxMouses;

    static int IOCTL_SET_PRECEDENCE  => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_GET_PRECEDENCE  => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_SET_FILTER      => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_GET_FILTER      => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_SET_EVENT       => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_WRITE           => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_READ            => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static int IOCTL_GET_HARDWARE_ID => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x880, METHOD_BUFFERED, FILE_ANY_ACCESS);

    public struct KeyboardInputData
    {
        public ushort UnitID;
        public ushort MakeCode;
        public ushort Flags;
        public ushort Reserved;
        public uint ExtraInformation;
    }

    public struct MouseInputData
    {
        public ushort UnitId;
        public ushort Flags;
        public ushort ButtonFlags;
        public ushort ButtonData;
        public uint RawButtons;
        public int LastX;
        public int LastY;
        public uint ExtraInformation;
    }

    public struct DeviceArray
    {
        public nint Handle;
        public nint UnEmpty;
    }

    public enum KeyState
    {
        Down = 0x00,
        Up   = 0x01,
        E0   = 0x02,
        E1   = 0x04,

        TerminalServerSetLed   = 0x08,
        TerminalServerShadow   = 0x10,
        TerminalServerVkPacket = 0x20,
    };

    [Flags]
    public enum FilterKeyState
    {
        None = 0x0000,
        All  = 0xFFFF,

        Down = KeyState.Up,
        Up   = KeyState.Up << 1,
        E0   = KeyState.E0 << 1,
        E1   = KeyState.E1 << 1,

        TerminalServerSetLed   = KeyState.TerminalServerSetLed << 1,
        TerminalServerShadow   = KeyState.TerminalServerShadow << 1,
        TerminalServerVkPacket = KeyState.TerminalServerVkPacket << 1
    };

    public enum MouseState
    {
        LeftButtonDown   = 0x001,
        LeftButtonUp     = 0x002,
        RightButtonDown  = 0x004,
        RightButtonUp    = 0x008,
        MiddleButtonDown = 0x010,
        MiddleButtonUp   = 0x020,

        Button1Down = LeftButtonDown,
        Button1Up   = LeftButtonUp,
        Button2Down = RightButtonDown,
        Button2Up   = RightButtonUp,
        Button3Down = MiddleButtonDown,
        Button3Up   = MiddleButtonUp,

        Button4Down = 0x040,
        Button4Up   = 0x080,
        Button5Down = 0x100,
        Button5Up   = 0x200,

        Wheel  = 0x400,
        HWheel = 0x800
    };

    [Flags]
    public enum FilterMouseState
    {
        None = 0x0000,
        All = 0xFFFF,

        LeftButtonDown   = MouseState.LeftButtonDown,
        LeftButtonUp     = MouseState.LeftButtonUp,
        RightButtonDown  = MouseState.RightButtonDown,
        RightButtonUp    = MouseState.RightButtonUp,
        MiddleButtonDown = MouseState.MiddleButtonDown,
        MiddleButtonUp   = MouseState.MiddleButtonUp,

        Button1Down = MouseState.Button1Down,
        Button1Up   = MouseState.Button1Up,
        Button2Down = MouseState.Button2Down,
        Button2Up   = MouseState.Button2Up,
        Button3Down = MouseState.Button3Down,
        Button3Up   = MouseState.Button3Up,

        Button4Down = MouseState.Button4Down,
        Button4Up   = MouseState.Button4Up,
        Button5Down = MouseState.Button5Down,
        Button5Up   = MouseState.Button5Up,

        Wheel  = MouseState.Wheel,
        HWheel = MouseState.HWheel,

        MOVE = 0x1000
    };

    public enum MouseFlag
    {
       MoveRelative            = 0x000,
       MoveAbsolute            = 0x001,
       VirtualDesktop          = 0x002,
       AttributesChanged       = 0x004,
       MoveNoCoalesce          = 0x008,
       TerminalServerSrcShadow = 0x100,
    };

    public struct MouseStroke
    {
        public ushort State;
        public ushort Flags;
        public ushort Rolling;
        public int X;
        public int Y;
        public uint Information;
    }

    public struct KeyStroke
    {
        public ushort Code;
        public ushort State;
        public uint Information;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct Stroke
    {
        [FieldOffset(0x00)]
        public MouseStroke MouseStroke;

        [FieldOffset(0x00)]
        public KeyStroke KeyStroke;
    }

    static int CTL_CODE(int deviceType, int function, int method, int access) => deviceType << 16 | access << 14 | function << 2 | method;

    public static InterceptionContext interception_create_context()
    {
        DeviceArray* device_array = null;
        ReadOnlySpan<byte> device_name = "\\\\.\\interception00\0"u8;
        fixed (byte* device_name_pointer = device_name)
        {
            int bytes_returned;
            device_array = (DeviceArray*)HeapAlloc(GetProcessHeap(), HeapFlags.ZeroMemory, MaxDevices * sizeof(DeviceArray));
            if (device_array is null)
                return default;

            nint* zero_padded_handle = stackalloc nint[2];
            for (InterceptionDevice i = 0; i < MaxDevices; i++)
            {
                zero_padded_handle[0] = zero_padded_handle[1] = default;

                *(ushort*)&device_name_pointer[device_name.Length - 3] = (ushort)(('0' + (i / 10)) | ('0' + (i % 10)) << 8);

                device_array[i].Handle = CreateFileA(device_name_pointer, AccessMask.GenericRead, FileShareMode.None, null, FileCreationDisposition.OpenExisting, default, default);
                if (device_array[i].Handle == INVALID_HANDLE_VALUE)
                {
                    interception_destroy_context((InterceptionContext)device_array);
                    return default;
                }

                device_array[i].UnEmpty = CreateEventA(default, true, false, null);
                if (device_array[i].UnEmpty == default)
                {
                    interception_destroy_context((InterceptionContext)device_array);
                    return 0;
                }
                zero_padded_handle[0] = device_array[i].UnEmpty;

                if (!DeviceIoControl(device_array[i].Handle, IOCTL_SET_EVENT, zero_padded_handle, sizeof(nint) * 2, null, 0, &bytes_returned, null))
                {
                    interception_destroy_context((InterceptionContext)device_array);
                    return 0;
                }
            }

            return (InterceptionContext)device_array;
        }
    }

    public static void interception_destroy_context(InterceptionContext context)
    {
        if (context == default)
            return;

        var device_array = (DeviceArray*)context;

        for (var i = 0; i < MaxDevices; ++i)
        {
            if (device_array[i].Handle != INVALID_HANDLE_VALUE)
                CloseHandle(device_array[i].Handle);

            if (device_array[i].UnEmpty != default)
                CloseHandle(device_array[i].UnEmpty);
        }


        HeapFree(GetProcessHeap(), 0, context);
    }

    public static InterceptionPrecedence interception_get_precedence(InterceptionContext context, InterceptionDevice device)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        InterceptionPrecedence precedence = 0;
        int bytes_returned;

        if (context != default && device_array[device - 1].Handle != default)
            DeviceIoControl(device_array[device - 1].Handle, IOCTL_GET_PRECEDENCE, null, 0, &precedence, sizeof(InterceptionPrecedence), &bytes_returned, null);

        return precedence;
    }

    public static void interception_set_precedence(InterceptionContext context, InterceptionDevice device, InterceptionPrecedence precedence)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        int bytes_returned;

        if (context != default && device_array[device - 1].Handle != default)
            DeviceIoControl(device_array[device - 1].Handle, IOCTL_SET_PRECEDENCE, & precedence, sizeof(InterceptionPrecedence), null, 0, &bytes_returned, null);
    }

    public static InterceptionFilter interception_get_filter(InterceptionContext context, InterceptionDevice device)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        InterceptionFilter filter = 0;
        int bytes_returned;

        if (context != default && device_array[device - 1].Handle != default)
            DeviceIoControl(device_array[device - 1].Handle, IOCTL_GET_FILTER, null, 0, &filter, sizeof(InterceptionFilter), &bytes_returned, null);

        return filter;
    }

    public static void interception_set_filter(InterceptionContext context, Predicate interception_predicate, InterceptionFilter filter)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        InterceptionDevice i;
        int bytes_returned;

        if (context != default)
            for (i = 0; i < MaxDevices; ++i)
                if (device_array[i].Handle != default && interception_predicate(i + 1) != default)
                    DeviceIoControl(device_array[i].Handle, IOCTL_SET_FILTER, &filter, sizeof(InterceptionFilter), null, 0, &bytes_returned, null);
    }

    public static InterceptionDevice interception_wait(InterceptionContext context)
    {
        return interception_wait_with_timeout(context, INFINITE);
    }

    public static InterceptionDevice interception_wait_with_timeout(InterceptionContext context, int milliseconds)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        nint* wait_handles = stackalloc nint[MaxDevices];
        int i, j, k;

        if (context == default) 
            return default;

        for (i = 0, j = 0; i < MaxDevices; ++i)
        {
            if (device_array[i].UnEmpty != default)
                wait_handles[j++] = device_array[i].UnEmpty;
        }

        k = WaitForMultipleObjects(j, wait_handles, false, milliseconds);

        if (k == WAIT_FAILED || k == WAIT_TIMEOUT) return 0;

        for (i = 0, j = 0; i < MaxDevices; ++i)
        {
            if (device_array[i].UnEmpty != default)
                if (k == j++)
                    break;
        }

        return i + 1;
    }

    public static int interception_send(InterceptionContext context, InterceptionDevice device, Stroke *stroke, uint nstroke)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        int strokeswritten = 0;

        if(context == 0 || nstroke == 0 || interception_is_invalid(device) || device_array[device - 1].Handle == default)
            return 0;

        if(interception_is_keyboard(device))
        {
            var rawstrokes = (KeyboardInputData*)HeapAlloc(GetProcessHeap(), 0, nstroke * sizeof(KeyboardInputData));
            uint i;

            if(rawstrokes == default) 
                return 0;

            for(i = 0; i < nstroke; ++i)
            {
                KeyStroke* key_stroke = (KeyStroke*)stroke;

                rawstrokes[i].UnitID = 0;
                rawstrokes[i].MakeCode = key_stroke[i].Code;
                rawstrokes[i].Flags = key_stroke[i].State;
                rawstrokes[i].Reserved = 0;
                rawstrokes[i].ExtraInformation = key_stroke[i].Information;
            }

            DeviceIoControl(device_array[device - 1].Handle, IOCTL_WRITE, rawstrokes, nstroke * sizeof(KeyboardInputData), null, 0, &strokeswritten, null);

            HeapFree(GetProcessHeap(), 0, rawstrokes);

            strokeswritten /= sizeof(KeyboardInputData);
        }
        else
        {
            MouseInputData* rawstrokes = (MouseInputData*)HeapAlloc(GetProcessHeap(), 0, nstroke * sizeof(MouseInputData));
            uint i;

            if(rawstrokes == default) 
                return 0;

            for(i = 0; i < nstroke; ++i)
            {
                MouseStroke* mouse_stroke = (MouseStroke*)stroke;

                rawstrokes[i].UnitId = 0;
                rawstrokes[i].Flags = mouse_stroke[i].Flags;
                rawstrokes[i].ButtonFlags = mouse_stroke[i].State;
                rawstrokes[i].ButtonData = mouse_stroke[i].Rolling;
                rawstrokes[i].RawButtons = 0;
                rawstrokes[i].LastX = mouse_stroke[i].X;
                rawstrokes[i].LastY = mouse_stroke[i].Y;
                rawstrokes[i].ExtraInformation = mouse_stroke[i].Information;
            }

            DeviceIoControl(device_array[device - 1].Handle, IOCTL_WRITE, rawstrokes, nstroke * sizeof(MouseInputData), null, 0, &strokeswritten, null);

            HeapFree(GetProcessHeap(), 0,  rawstrokes);

            strokeswritten /= sizeof(MouseInputData);
        }

        return strokeswritten;
    }

    public static int interception_receive(InterceptionContext context, InterceptionDevice device, Stroke* stroke, uint nstroke)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        int strokesread = 0;

        if (context == 0 || nstroke == 0 || interception_is_invalid(device) || device_array[device - 1].Handle == default) 
            return 0;

        if (interception_is_keyboard(device))
        {
            KeyboardInputData* rawstrokes = (KeyboardInputData*)Kernel32.HeapAlloc(GetProcessHeap(), 0, nstroke * sizeof(KeyboardInputData));
            int i;
            if (rawstrokes == null) 
                return 0;

            DeviceIoControl(device_array[device - 1].Handle, IOCTL_READ, null, 0, rawstrokes, (int)nstroke * sizeof(KeyboardInputData), &strokesread, null);

            strokesread /= sizeof(KeyboardInputData);

            for (i = 0; i < strokesread; i++)
        {
                KeyStroke* key_stroke = (KeyStroke*)stroke;

                key_stroke[i].Code = rawstrokes[i].MakeCode;
                key_stroke[i].State = rawstrokes[i].Flags;
                key_stroke[i].Information = rawstrokes[i].ExtraInformation;
            }

            HeapFree(GetProcessHeap(), 0, rawstrokes);
        }
        else
        {
            MouseInputData* rawstrokes = (MouseInputData*)HeapAlloc(GetProcessHeap(), 0, nstroke * sizeof(MouseInputData));
            int i;
            if (rawstrokes == null)
                return 0;

            DeviceIoControl(device_array[device - 1].Handle, IOCTL_READ, null, 0, rawstrokes, nstroke * sizeof(MouseInputData), &strokesread, null);

            strokesread /= sizeof(MouseInputData);

            for (i = 0; i < strokesread; i++)
            {
                MouseStroke* mouse_stroke = (MouseStroke*)stroke;

                mouse_stroke[i].Flags = rawstrokes[i].Flags;
                mouse_stroke[i].State = rawstrokes[i].ButtonFlags;
                mouse_stroke[i].Rolling = rawstrokes[i].ButtonData;
                mouse_stroke[i].X = rawstrokes[i].LastX;
                mouse_stroke[i].Y = rawstrokes[i].LastY;
                mouse_stroke[i].Information = rawstrokes[i].ExtraInformation;
            }

            HeapFree(GetProcessHeap(), 0, rawstrokes);
        }

        return strokesread;
    }

    public static int interception_get_hardware_id(InterceptionContext context, InterceptionDevice device, void* hardware_id_buffer, uint buffer_size)
    {
        DeviceArray* device_array = (DeviceArray*)context;
        int output_size = 0;

        if (context == default || interception_is_invalid(device) || device_array[device - 1].Handle == default) 
            return 0;

        DeviceIoControl(device_array[device - 1].Handle, IOCTL_GET_HARDWARE_ID, null, 0, hardware_id_buffer, buffer_size, &output_size, null);

        return output_size;
    }

    public static bool interception_is_invalid(InterceptionDevice device)
    {
        return !interception_is_keyboard(device) && !interception_is_mouse(device);
    }

    static int INTERCEPTION_KEYBOARD(int index) => index + 1;

    public static bool interception_is_keyboard(InterceptionDevice device)
    {
        return device >= INTERCEPTION_KEYBOARD(0) && device <= INTERCEPTION_KEYBOARD(MaxKeyboards - 1);
    }

    static int INTERCEPTION_MOUSE(int index) => MaxKeyboards + index + 1;

    public static bool interception_is_mouse(InterceptionDevice device)
    {
        return device >= INTERCEPTION_MOUSE(0) && device <= INTERCEPTION_MOUSE(MaxMouses - 1);
    }
}