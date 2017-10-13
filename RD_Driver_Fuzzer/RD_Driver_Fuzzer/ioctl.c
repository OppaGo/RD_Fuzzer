#include <stdio.h>
#include <Windows.h>
#include "ioctl.h"


void IOCTLPrintDevice(const int32 DeviceType)
{
	switch (DeviceType)
	{
	case FILE_DEVICE_BEEP:
		printf("[+] FILE_DEVICE_BEEP : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_CD_ROM:
		printf("[+] FILE_DEVICE_CD_ROM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
		printf("[+] FILE_DEVICE_CD_ROM_FILE_SYSTEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_CONTROLLER:
		printf("[+] FILE_DEVICE_CONTROLLER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DATALINK:
		printf("[+] FILE_DEVICE_DATALINK : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DFS:
		printf("[+] FILE_DEVICE_DFS : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DISK:
		printf("[+] FILE_DEVICE_DISK : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DISK_FILE_SYSTEM:
		printf("[+] FILE_DEVICE_DISK_FILE_SYSTEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_FILE_SYSTEM:
		printf("[+] FILE_DEVICE_FILE_SYSTEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_INPORT_PORT:
		printf("[+] FILE_DEVICE_INPORT_PORT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_KEYBOARD:
		printf("[+] FILE_DEVICE_KEYBOARD : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MAILSLOT:
		printf("[+] FILE_DEVICE_MAILSLOT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MIDI_IN:
		printf("[+] FILE_DEVICE_MIDI_IN : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MIDI_OUT:
		printf("[+] FILE_DEVICE_MIDI_OUT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MOUSE:
		printf("[+] FILE_DEVICE_MOUSE : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MULTI_UNC_PROVIDER:
		printf("[+] FILE_DEVICE_MULTI_UNC_PROVIDER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_NAMED_PIPE:
		printf("[+] FILE_DEVICE_NAMED_PIPE : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_NETWORK:
		printf("[+] FILE_DEVICE_NETWORK : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_NETWORK_BROWSER:
		printf("[+] FILE_DEVICE_NETWORK_BROWSER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_NETWORK_FILE_SYSTEM:
		printf("[+] FILE_DEVICE_NETWORK_FILE_SYSTEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_NULL:
		printf("[+] FILE_DEVICE_NULL : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_PARALLEL_PORT:
		printf("[+] FILE_DEVICE_PARALLER_PORT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_PHYSICAL_NETCARD:
		printf("[+] FILE_DEVICE_PHYSICAL_NETCARD : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_PRINTER:
		printf("[+] FILE_DEVICE_PRINTER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SCANNER:
		printf("[+] FILE_DEVICE_SCANNER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SERIAL_MOUSE_PORT:
		printf("[+] FILE_DEVICE_SERIAL_MOUSE_PORT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SERIAL_PORT:
		printf("[+] FILE_DEVICE_SERIAL_PORT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SCREEN:
		printf("[+] FILE_DEVICE_SCREEN : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SOUND:
		printf("[+] FILE_DEVICE_SOUND : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_STREAMS:
		printf("[+] FILE_DEVICE_STREAMS : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_TAPE:
		printf("[+] FILE_DEVICE_TAPE : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_TAPE_FILE_SYSTEM:
		printf("[+] FILE_DEVICE_TAPE_FILE_SYSTEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_TRANSPORT:
		printf("[+] FILE_DEVICE_TRANSPORT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_UNKNOWN:
		printf("[+] FILE_DEVICE_UNKNOWN : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_VIDEO:
		printf("[+] FILE_DEVICE_VIDEO : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_VIRTUAL_DISK:
		printf("[+] FILE_DEVICE_VIRTUAL_DISK : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_WAVE_IN:
		printf("[+] FILE_DEVICE_WAVE_IN : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_WAVE_OUT:
		printf("[+] FILE_DEVICE_WAVE_OUT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_8042_PORT:
		printf("[+] FILE_DEVICE_8042_PORT : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_NETWORK_REDIRECTOR:
		printf("[+] FILE_DEVICE_NETWORK_REDIRECTOR : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_BATTERY:
		printf("[+] FILE_DEVICE_BATTERY : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_BUS_EXTENDER:
		printf("[+] FILE_DEVICE_BUS_EXTENDER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MODEM:
		printf("[+] FILE_DEVICE_MODEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_VDM:
		printf("[+] FILE_DEVICE_VDM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_MASS_STORAGE:
		printf("[+] FILE_DEVICE_MASS_STORAGE : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SMB:
		printf("[+] FILE_DEVICE_SMB : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_KS:
		printf("[+] FILE_DEVICE_KS : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_CHANGER:
		printf("[+] FILE_DEVICE_CHANGER : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_SMARTCARD:
		printf("[+] FILE_DEVICE_SMARTCARD : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_ACPI:
		printf("[+] FILE_DEVICE_ACPI : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DVD:
		printf("[+] FILE_DEVICE_DVD : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_FULLSCREEN_VIDEO:
		printf("[+] FILE_DEVICE_FULLSCREEN_VIDEO : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DFS_FILE_SYSTEM:
		printf("[+] FILE_DEVICE_DFS_FILE_SYSTEM : 0x%x \n", DeviceType);
		break;
	case FILE_DEVICE_DFS_VOLUME:
		printf("[+] FILE_DEVICE_DFS_VOLUME : 0x%x \n", DeviceType);
		break;
	default:
		fprintf(stderr, "[-] Unknown DeviceType : 0x%x \n", DeviceType);
		break;
	}
}

void IOCTLPrintMethod(const int32 Method)
{
	switch (Method)
	{
	case METHOD_BUFFERED:
		printf("[+] METHOD_BUFFERED : 0x%x \n", Method);
		break;
	case METHOD_OUT_DIRECT:
		printf("[+] METHOD_OUT_DIRECT : 0x%x \n", Method);
		break;
	case METHOD_IN_DIRECT:
		printf("[+] METHOD_IN_DIRECT : 0x%x \n", Method);
		break;
	case METHOD_NEITHER:
		printf("[+] METHOD_NEITHER : 0x%x \n", Method);
		break;
	default:
		fprintf(stderr, "[-] Unknown Method : 0x%x \n", Method);
		break;
	}
}

void IOCTLPrintAccess(const int32 Access)
{
	switch (Access)
	{
	case FILE_ANY_ACCESS:
		printf("[+] FILE_ANY_ACCESS : 0x%x \n", Access);
		break;
	case FILE_READ_ACCESS:
		printf("[+] FILE_READ_ACCESS : 0x%x \n", Access);
		break;
	case FILE_WRITE_ACCESS:
		printf("[+] FILE_WRITE_ACCESS : 0x%x \n", Access);
		break;
	case FILE_READ_ACCESS | FILE_WRITE_ACCESS:
		printf("[+] FILE_READ_ACCESS | FILE_WRITE_ACCESS : 0x%x \n", Access);
		break;
	default:
		fprintf(stderr, "[-] Unknown Access : 0x%x \n", Access);
		break;
	}
}

void PrintIOCTLValue(int32 ioctl_code)
{
	printf("[+] DeviceType : 0x%x\n", CTL_DEVICE(ioctl_code));
	printf("[+] Access : 0x%x\n", CTL_ACCESS(ioctl_code));
	printf("[+] Function : 0x%x\n", CTL_FUNCTION(ioctl_code));
	printf("[+] Method : 0x%x\n", CTL_METHOD(ioctl_code));
}
