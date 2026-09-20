package acmejob

import "errors"

// Worker exit codes are a deliberately small, stable protocol. The worker
// never sends upstream error text because DNS APIs and CAs can echo secrets.
const (
	WorkerExitInput        = 2
	WorkerExitRegistration = 3
	WorkerExitProvider     = 4
	WorkerExitValidation   = 5
	WorkerExitOutput       = 6
	WorkerExitDelegation   = 7
	WorkerExitPropagation  = 8
)

var (
	ErrWorkerInput   = errors.New("Внутренняя проверка задания ACME не пройдена.")
	ErrDNSProvider   = errors.New("DNS: не удалось подготовить доступ или обновить временную TXT-запись.")
	ErrPropagation   = errors.New("DNS: временная TXT-запись не подтверждена рекурсивными и авторитетными серверами.")
	ErrRegistration  = errors.New("CA: регистрация ACME-аккаунта не подтверждена.")
	ErrCAValidation  = errors.New("CA: проверка домена или выпуск сертификата не подтверждены.")
	ErrWorker        = errors.New("ACME worker не завершил выпуск.")
	ErrWorkerStart   = errors.New("Не удалось запустить ACME worker.")
	ErrWorkerOutput  = errors.New("ACME worker вернул неполный результат.")
	ErrWorkerCancel  = errors.New("Выпуск ACME был остановлен до завершения.")
	ErrWorkerTimeout = errors.New("Время работы ACME worker истекло.")
	ErrLocalInstall  = errors.New("Локальная установка сертификата не подтверждена.")
)

// WorkerFailure maps only allowlisted worker exit codes to safe status errors.
// It intentionally cannot expose worker stderr or any upstream error text.
func WorkerFailure(exitCode int) error {
	switch exitCode {
	case WorkerExitInput:
		return ErrWorkerInput
	case WorkerExitRegistration:
		return ErrRegistration
	case WorkerExitProvider:
		return ErrDNSProvider
	case WorkerExitValidation:
		return ErrCAValidation
	case WorkerExitOutput:
		return ErrWorkerOutput
	case WorkerExitDelegation:
		return ErrDelegation
	case WorkerExitPropagation:
		return ErrPropagation
	default:
		return ErrWorker
	}
}
