package domainset

import "strings"

type mapMembership struct{ exact, suffix map[string][]uint32 }

func compileMapMembership(exact, suffix []membership) *mapMembership {
	i := &mapMembership{make(map[string][]uint32), make(map[string][]uint32)}
	for _, entry := range exact {
		i.exact[entry.name] = append(i.exact[entry.name], entry.id)
	}
	for _, entry := range suffix {
		i.suffix[entry.name] = append(i.suffix[entry.name], entry.id)
	}
	return i
}

func (i *mapMembership) Match(name string, visit func(uint32)) {
	for _, id := range i.exact[name] {
		visit(id)
	}
	for suffix := name; suffix != ""; {
		for _, id := range i.suffix[suffix] {
			visit(id)
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
}
