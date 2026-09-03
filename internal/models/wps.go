/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

package models

import (
	"strconv"
	"strings"
)


const (
    methodUSB = 1 << iota // 1 << 0 = 1   (0x0001)
    methodETHER           // 1 << 1 = 2   (0x0002)
    methodLAB             // 1 << 2 = 4   (0x0004)
    methodDISP            // 1 << 3 = 8   (0x0008)
    methodEXTNFC          // 1 << 4 = 16  (0x0010)
    methodINTNFC          // 1 << 5 = 32  (0x0020)
    methodNFCINTF         // 1 << 6 = 64  (0x0040)
    methodPBC             // 1 << 7 = 128 (0x0080)
    methodKPAD            // 1 << 8 = 256 (0x0100)
)



type WPSInfo struct {
	Version        int
	IsConfigured   bool
	ConfigMethods  uint16
	APSetupLocked  bool
}



func (info WPSInfo) String() string {
	if info.Version == 0 && !info.IsConfigured && info.ConfigMethods == 0 && !info.APSetupLocked {
		return "?????"
	}

	var b strings.Builder

	if info.Version > 0 {
		b.WriteString("v")
		b.WriteString(formatVersion(info.Version))
	}

	if info.IsConfigured {
		if b.Len() > 0 { b.WriteByte(' ') }
		b.WriteString("configured")
	} else {
		if b.Len() > 0 { b.WriteByte(' ') }
		b.WriteString("unconfigured")
	}

	methods := info.methodsString()
	if methods != "" {
		if b.Len() > 0 { b.WriteByte(' ') }
		b.WriteString(methods)
	}

	if info.APSetupLocked {
		if b.Len() > 0 { b.WriteByte(' ') }
		b.WriteString("locked")
	}

	return b.String()
}



func formatVersion(v int) string {
	major := v >> 4
	minor := v & 0x0F

	if minor == 0 {
		return strconv.Itoa(major)
	}

	return strconv.Itoa(major) + "." + strconv.Itoa(minor)
}



func (info WPSInfo) methodsString() string {
	var b strings.Builder
	first := true

	appendMethod := func(name string) {
		if !first { b.WriteByte(' ') }
		b.WriteString(name)
		first = false
	}

	if info.hasUSB()     { appendMethod("USB")     }
	if info.hasETHER()   { appendMethod("ETHER")   }
	if info.hasLAB()     { appendMethod("LAB")     }
	if info.hasDISP()    { appendMethod("DISP")    }
	if info.hasEXTNFC()  { appendMethod("EXTNFC")  }
	if info.hasINTNFC()  { appendMethod("INTNFC")  }
	if info.hasNFCINTF() { appendMethod("NFCINTF") }
	if info.hasPBC()     { appendMethod("PBC")     }
	if info.hasKPAD()    { appendMethod("KPAD")    }

	return b.String()
}



func (info WPSInfo) hasUSB()     bool { return info.ConfigMethods&methodUSB != 0     }
func (info WPSInfo) hasETHER()   bool { return info.ConfigMethods&methodETHER != 0   }
func (info WPSInfo) hasLAB()     bool { return info.ConfigMethods&methodLAB != 0     }
func (info WPSInfo) hasDISP()    bool { return info.ConfigMethods&methodDISP != 0    }
func (info WPSInfo) hasEXTNFC()  bool { return info.ConfigMethods&methodEXTNFC != 0  }
func (info WPSInfo) hasINTNFC()  bool { return info.ConfigMethods&methodINTNFC != 0  }
func (info WPSInfo) hasNFCINTF() bool { return info.ConfigMethods&methodNFCINTF != 0 }
func (info WPSInfo) hasPBC()     bool { return info.ConfigMethods&methodPBC != 0     }
func (info WPSInfo) hasKPAD()    bool { return info.ConfigMethods&methodKPAD != 0    }



func (info WPSInfo) Len() int {
    total := 0

    if info.Version > 0 {
		total += 4  // 1.0v or 2.0v
    }

    if info.IsConfigured {
        total += 11  // ' ' + configured(11)
    } else {
        total += 13  // ' ' + unconfigured(12)
    }

	if info.ConfigMethods != 0 || info.APSetupLocked {
        total++ 
    }

    if info.ConfigMethods != 0 {
        total += info.lenMethods()
    }

    if info.APSetupLocked {
        total += 7  // ' ' + locked
    }

    return total
}



func (info WPSInfo) lenMethods() int {
	var lenMethods int

	if info.hasUSB()     { lenMethods += 4 } // ' ' + USB    
	if info.hasETHER()   { lenMethods += 6 } // ' ' + ETHER  
	if info.hasLAB()     { lenMethods += 4 } // ' ' + LAB    
	if info.hasDISP()    { lenMethods += 5 } // ' ' + DISP   
	if info.hasEXTNFC()  { lenMethods += 7 } // ' ' + EXTNFC 
	if info.hasINTNFC()  { lenMethods += 7 } // ' ' + INTNFC 
	if info.hasNFCINTF() { lenMethods += 8 } // ' ' + NFCINTF
	if info.hasPBC()     { lenMethods += 4 } // ' ' + PBC    
	if info.hasKPAD()    { lenMethods += 5 } // ' ' + KPAD   

	return lenMethods
}