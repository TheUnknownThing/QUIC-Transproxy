package safemap

import (
	"sync"
)

type SafeMap[K comparable, V any] struct {
	m sync.Map
}

func New[K comparable, V any]() *SafeMap[K, V] {
	return &SafeMap[K, V]{}
}

func (sm *SafeMap[K, V]) Set(key K, value V) {
	sm.m.Store(key, value)
}

func (sm *SafeMap[K, V]) Get(key K) (V, bool) {
	value, ok := sm.m.Load(key)
	if !ok {
		var zero V
		return zero, false
	}
	return value.(V), ok
}

func (sm *SafeMap[K, V]) GetOrDefault(key K, defaultValue V) V {
	value, ok := sm.m.Load(key)
	if !ok {
		return defaultValue
	}
	return value.(V)
}

func (sm *SafeMap[K, V]) Delete(key K) {
	sm.m.Delete(key)
}

func (sm *SafeMap[K, V]) Has(key K) bool {
	_, ok := sm.m.Load(key)
	return ok
}

func (sm *SafeMap[K, V]) Len() int {
	length := 0
	sm.m.Range(func(key, value interface{}) bool {
		length++
		return true
	})
	return length
}

func (sm *SafeMap[K, V]) Keys() []K {
	keys := make([]K, 0)
	sm.m.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(K))
		return true
	})
	return keys
}

func (sm *SafeMap[K, V]) Values() []V {
	values := make([]V, 0)
	sm.m.Range(func(key, value interface{}) bool {
		values = append(values, value.(V))
		return true
	})
	return values
}

func (sm *SafeMap[K, V]) Clear() {
	sm.m = sync.Map{}
}

func (sm *SafeMap[K, V]) Range(f func(key K, value V) bool) {
	sm.m.Range(func(key, value interface{}) bool {
		return f(key.(K), value.(V))
	})
}

func (sm *SafeMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	a, l := sm.m.LoadOrStore(key, value)
	return a.(V), l
}

func (sm *SafeMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	v, l := sm.m.LoadAndDelete(key)
	if !l {
		var zero V
		return zero, l
	}
	return v.(V), l
}
