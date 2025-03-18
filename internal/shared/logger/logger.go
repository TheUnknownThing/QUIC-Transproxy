package logger

import (
	"log"
	"os"
)

type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

type SimpleLogger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
}

func NewSimpleLogger() *SimpleLogger {
	return &SimpleLogger{
		debugLogger: log.New(os.Stdout, "[DEBUG] ", log.LstdFlags),
		infoLogger:  log.New(os.Stdout, "[INFO] ", log.LstdFlags),
		warnLogger:  log.New(os.Stdout, "[WARN] ", log.LstdFlags),
		errorLogger: log.New(os.Stderr, "[ERROR] ", log.LstdFlags),
	}
}

func (l *SimpleLogger) Debug(format string, args ...interface{}) {
	l.debugLogger.Printf(format, args...)
}

func (l *SimpleLogger) Info(format string, args ...interface{}) {
	l.infoLogger.Printf(format, args...)
}

func (l *SimpleLogger) Warn(format string, args ...interface{}) {
	l.warnLogger.Printf(format, args...)
}

func (l *SimpleLogger) Error(format string, args ...interface{}) {
	l.errorLogger.Printf(format, args...)
}
