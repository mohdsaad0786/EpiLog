package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type Sample struct {
	PID   uint32
	Bytes []byte
}
type Capture struct {
	reader   *perf.Reader
	attached link.Link
	program  *ebpf.Program
	events   *ebpf.Map
	once     sync.Once
}

func Open(libssl string, receive func(Sample)) (*Capture, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("libssl capture requires Linux")
	}
	var bufferOffset, lengthOffset int16
	switch runtime.GOARCH {
	case "amd64":
		bufferOffset, lengthOffset = 104, 96
	case "arm64":
		bufferOffset, lengthOffset = 8, 16
	default:
		return nil, errors.New("unsupported architecture")
	}
	_ = rlimit.RemoveMemlock()
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "bhai_tls_events", Type: ebpf.PerfEventArray, KeySize: 4, ValueSize: 4, MaxEntries: uint32(runtime.NumCPU())})
	if err != nil {
		return nil, err
	}
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R7, asm.R1),
		asm.LoadMem(asm.R6, asm.R1, bufferOffset, asm.DWord),
		asm.LoadMem(asm.R8, asm.R1, lengthOffset, asm.DWord),
		asm.JSLE.Imm(asm.R8, 0, "exit"),
		asm.JLE.Imm(asm.R8, 256, "bounded"),
		asm.Mov.Imm(asm.R8, 256),
		asm.FnGetCurrentPidTgid.Call().WithSymbol("bounded"),
		asm.StoreMem(asm.R10, -272, asm.R0, asm.DWord),
		asm.StoreMem(asm.R10, -264, asm.R8, asm.Word),
		asm.StoreImm(asm.R10, -260, 0, asm.Word),
	}
	for offset := int16(-256); offset < 0; offset += 8 {
		instructions = append(instructions, asm.StoreImm(asm.R10, offset, 0, asm.DWord))
	}
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R10), asm.Add.Imm(asm.R1, -256),
		asm.Mov.Reg(asm.R2, asm.R8), asm.Mov.Reg(asm.R3, asm.R6), asm.FnProbeRead.Call(),
		asm.JSLT.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R1, asm.R7), asm.LoadMapPtr(asm.R2, events.FD()), asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.R10), asm.Add.Imm(asm.R4, -272), asm.Mov.Imm(asm.R5, 272),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return(),
	)
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "bhai_ssl_write", Type: ebpf.Kprobe, Instructions: instructions, License: "GPL"})
	if err != nil {
		events.Close()
		return nil, fmt.Errorf("load SSL_write uprobe: %w", err)
	}
	executable, err := link.OpenExecutable(libssl)
	if err != nil {
		program.Close()
		events.Close()
		return nil, err
	}
	attached, err := executable.Uprobe("SSL_write", program, nil)
	if err != nil {
		program.Close()
		events.Close()
		return nil, fmt.Errorf("attach SSL_write: %w", err)
	}
	reader, err := perf.NewReader(events, 4096)
	if err != nil {
		attached.Close()
		program.Close()
		events.Close()
		return nil, err
	}
	capture := &Capture{reader: reader, attached: attached, program: program, events: events}
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					fmt.Fprintf(os.Stderr, "libssl perf reader: %v\n", err)
				}
				return
			}
			if record.LostSamples != 0 || len(record.RawSample) < 272 {
				continue
			}
			size := binary.NativeEndian.Uint32(record.RawSample[8:12])
			if size > 256 {
				continue
			}
			sample := Sample{PID: binary.NativeEndian.Uint32(record.RawSample[0:4]), Bytes: append([]byte(nil), record.RawSample[16:16+size]...)}
			receive(sample)
		}
	}()
	return capture, nil
}
func (capture *Capture) Close() {
	capture.once.Do(func() {
		capture.reader.Close()
		capture.attached.Close()
		capture.program.Close()
		capture.events.Close()
	})
}
