package packet

type Packet struct {
	Data []byte
}

func NewPacket(data []byte) *Packet {
	return &Packet{
		Data: data,
	}
}

func (p *Packet) AppendSNIIdentifier(identifier []byte) {
	if len(identifier) != 2 {
		return
	}
	p.Data = append(p.Data, identifier...)
}

func (p *Packet) ExtractSNIIdentifier() []byte {
	dataLen := len(p.Data)
	if dataLen < 2 {
		return nil
	}
	defer p.restorePacket()
	return p.Data[dataLen-2:]
}

func (p *Packet) restorePacket() {
	if len(p.Data) < 2 {
		return
	}
	p.Data = p.Data[:len(p.Data)-2]
}

func (p *Packet) ExtractSNIIdentifierStr() string {
	identifier := p.ExtractSNIIdentifier()
	if identifier == nil {
		return ""
	}
	return string(identifier)
}

func (p *Packet) AppendSNIIdentifierStr(identifier string) {
	if len(identifier) != 2 {
		return
	}
	p.AppendSNIIdentifier([]byte(identifier))
}
