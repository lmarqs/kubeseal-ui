package secret

// Source records where an entry's value came from, so the wizard can show
// provenance without revealing the value itself.
type Source int

// Sources an entry value can have.
const (
	SourceLiteral Source = iota
	SourceFile
	SourceEditor
	// SourceExisting marks a key already sealed in a file being merged into.
	// Its value cannot be read back, only replaced.
	SourceExisting
)

// String names the source for display.
func (s Source) String() string {
	switch s {
	case SourceLiteral:
		return "literal"
	case SourceFile:
		return "file"
	case SourceEditor:
		return "editor"
	case SourceExisting:
		return "existing"
	default:
		return "unknown"
	}
}

// Entry is one key/value pair destined for the Secret. Values stay in memory
// only; they are never written anywhere but the sealed output.
type Entry struct {
	Key    Key
	Value  []byte
	Source Source
	// Path records the file a value was read from, when Source is SourceFile.
	Path string
}

// Entries is the ordered collection of entries being assembled, with at most one
// entry per key.
type Entries struct {
	items []Entry
}

// Set adds an entry, replacing any entry with the same key in place so the
// display order users built up is preserved.
func (e *Entries) Set(entry Entry) {
	for i := range e.items {
		if e.items[i].Key == entry.Key {
			e.items[i] = entry
			return
		}
	}
	e.items = append(e.items, entry)
}

// Get returns the entry stored under key.
func (e *Entries) Get(key Key) (Entry, bool) {
	for _, entry := range e.items {
		if entry.Key == key {
			return entry, true
		}
	}
	return Entry{}, false
}

// Has reports whether key is already present, which callers use to warn before
// replacing a value.
func (e *Entries) Has(key Key) bool {
	_, found := e.Get(key)
	return found
}

// Remove drops key, reporting whether it was there.
func (e *Entries) Remove(key Key) bool {
	for i, entry := range e.items {
		if entry.Key == key {
			zero(entry.Value)
			e.items = append(e.items[:i], e.items[i+1:]...)
			return true
		}
	}
	return false
}

// All returns the entries in order.
func (e *Entries) All() []Entry { return e.items }

// Len reports how many entries are held.
func (e *Entries) Len() int { return len(e.items) }

// Scrub overwrites every held value and empties the collection. Go offers no
// guarantee that no copy survives elsewhere, so this reduces exposure rather
// than eliminating it.
func (e *Entries) Scrub() {
	for _, entry := range e.items {
		zero(entry.Value)
	}
	e.items = nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
