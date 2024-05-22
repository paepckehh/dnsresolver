// package dnscache ...
package dnscache

// import
import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// minimal and heavy adapted fork of golang internal
// stdlib pakage sync.Map
//
// [sync/map.go]
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//
// INTERNAL API
//

// dnsMap ...
type dnsMap struct {
	mu     sync.Mutex
	read   atomic.Pointer[readOnly]
	dirty  map[uint64]*entry
	misses int
}

// entry ...
type entry struct {
	p atomic.Pointer[[]netip.Addr]
}

// add ...
func (m *dnsMap) add(key uint64, value []netip.Addr) {
	_, _ = m.swap(key, value)
}

// del ...
func (m *dnsMap) del(key uint64) {
	m.loadAndDelete(key)
}

// get ...
func (m *dnsMap) get(key uint64) (value []netip.Addr, ok bool) {
	read := m.loadReadOnly()
	e, ok := read.m[key]
	if !ok && read.amended {
		m.mu.Lock()
		read = m.loadReadOnly()
		e, ok = read.m[key]
		if !ok && read.amended {
			e, ok = m.dirty[key]
			m.missLocked()
		}
		m.mu.Unlock()
	}
	if !ok {
		return nil, false
	}
	return e.load()
}

//
// INTERNAL BACKEND
//

var (
	_nil  = []netip.Addr{}
	__nil = &_nil
)

type readOnly struct {
	m       map[uint64]*entry
	amended bool
}

var expunged = new([]netip.Addr)

func newEntry(i []netip.Addr) *entry {
	e := &entry{}
	e.p.Store(&i)
	return e
}

func (m *dnsMap) loadReadOnly() readOnly {
	if p := m.read.Load(); p != nil {
		return *p
	}
	return readOnly{}
}

func (e *entry) load() (value []netip.Addr, ok bool) {
	p := e.p.Load()
	if p == __nil || p == expunged {
		return _nil, false
	}
	return *p, true
}

func (e *entry) tryCompareAndSwap(old, newVal []netip.Addr) bool {
	p := e.p.Load()
	if p == __nil || p == expunged || *p != old {
		return false
	}
	nc := newVal
	for {
		if e.p.CompareAndSwap(p, &nc) {
			return true
		}
		p = e.p.Load()
		if p == __nil || p == expunged || *p != old {
			return false
		}
	}
}

func (e *entry) unexpungeLocked() (wasExpunged bool) {
	return e.p.CompareAndSwap(expunged, nil)
}

func (e *entry) swapLocked(i *[]netip.Addr) *[]netip.Addr {
	return e.p.Swap(i)
}

func (e *entry) delete() (value []netip.Addr, ok bool) {
	for {
		p := e.p.Load()
		if p == __nil || p == expunged {
			return _nil, false
		}
		if e.p.CompareAndSwap(p, nil) {
			return *p, true
		}
	}
}

func (m *dnsMap) missLocked() {
	m.misses++
	if m.misses < len(m.dirty) {
		return
	}
	m.read.Store(&readOnly{m: m.dirty})
	m.dirty = nil
	m.misses = 0
}

func (m *dnsMap) dirtyLocked() {
	if m.dirty != nil {
		return
	}

	read := m.loadReadOnly()
	m.dirty = make(map[uint64]*entry, len(read.m))
	for k, e := range read.m {
		if !e.tryExpungeLocked() {
			m.dirty[k] = e
		}
	}
}

func (e *entry) tryExpungeLocked() (isExpunged bool) {
	p := e.p.Load()
	for p == nil {
		if e.p.CompareAndSwap(nil, expunged) {
			return true
		}
		p = e.p.Load()
	}
	return p == expunged
}

func (m *dnsMap) swap(key uint64, value []netip.Addr) (previous []netip.Addr, loaded bool) {
	read := m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		if v, ok := e.trySwap(&value); ok {
			if v == nil {
				return nil, false
			}
			return *v, true
		}
	}

	m.mu.Lock()
	read = m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		if e.unexpungeLocked() {
			m.dirty[key] = e
		}
		if v := e.swapLocked(&value); v != nil {
			loaded = true
			previous = *v
		}
	} else if e, ok := m.dirty[key]; ok {
		if v := e.swapLocked(&value); v != nil {
			loaded = true
			previous = *v
		}
	} else {
		if !read.amended {
			m.dirtyLocked()
			m.read.Store(&readOnly{m: read.m, amended: true})
		}
		m.dirty[key] = newEntry(value)
	}
	m.mu.Unlock()
	return previous, loaded
}

func (m *dnsMap) loadAndDelete(key uint64) (value []netip.Addr, loaded bool) {
	read := m.loadReadOnly()
	e, ok := read.m[key]
	if !ok && read.amended {
		m.mu.Lock()
		read = m.loadReadOnly()
		e, ok = read.m[key]
		if !ok && read.amended {
			e, ok = m.dirty[key]
			delete(m.dirty, key)
			m.missLocked()
		}
		m.mu.Unlock()
	}
	if ok {
		return e.delete()
	}
	return nil, false
}

func (e *entry) trySwap(i *[]netip.Addr) (*[]netip.Addr, bool) {
	for {
		p := e.p.Load()
		if p == expunged {
			return nil, false
		}
		if e.p.CompareAndSwap(p, i) {
			return p, true
		}
	}
}
