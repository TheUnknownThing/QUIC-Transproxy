package logger

import (
	"log"
	"os"
)

const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

type Logger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	level       string
}

func NewLogger(level string) *Logger {
	return &Logger{
		debugLogger: log.New(os.Stdout, "[DEBUG] ", log.LstdFlags),
		infoLogger:  log.New(os.Stdout, "[INFO] ", log.LstdFlags),
		warnLogger:  log.New(os.Stdout, "[WARN] ", log.LstdFlags),
		errorLogger: log.New(os.Stderr, "[ERROR] ", log.LstdFlags),
		level:       level,
	}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level == LevelDebug {
		l.debugLogger.Printf(format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo {
		l.infoLogger.Printf(format, v...)
	}
}

func (l *Logger) Warn(format string, v ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelWarn {
		l.warnLogger.Printf(format, v...)
	}
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}
