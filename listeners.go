// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"container/list"
	"sync"
)

// CancelListenerFunc removes the listener it's associated with and cancels any
// future events sent to that listener.
//
// A CancelListenerFunc is idempotent:  after the first invocation, calling this
// closure will have no effect.
type CancelListenerFunc func()

// listeners is a generic container of listeners that is safe for concurrent access
// and concurrent dispatch of events through the visit method.
type listeners struct {
	lock      sync.Mutex
	listeners *list.List
}

// cancelListener creates an idempotent closure that removes the given linked list element.
func (l *listeners) cancelListener(e *list.Element) CancelListenerFunc {
	return func() {
		l.lock.Lock()
		defer l.lock.Unlock()

		// NOTE: Remove is idempotent: it will not do anything if e is not in the list
		l.listeners.Remove(e)
	}
}

// addListener inserts a new listener into the list and returns a closure
// that will remove the listener from the list.
func (l *listeners) addListener(newListener interface{}) CancelListenerFunc {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.listeners == nil {
		l.listeners = list.New()
	}

	e := l.listeners.PushBack(newListener)
	return l.cancelListener(e)
}

// visit applies the given closure to each listener in the list.  This method
// is atomic with respect to addListener.
func (l *listeners) visit(f func(interface{})) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.listeners == nil {
		return
	}

	for e := l.listeners.Front(); e != nil; e = e.Next() {
		f(e.Value)
	}
}
