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
	return p.Data[dataLen-2:]
}

func (p *Packet) RestorePacket() {
	if len(p.Data) < 2 {
		return
	}
	p.Data = p.Data[:len(p.Data)-2]
}
