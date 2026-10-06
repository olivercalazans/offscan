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
	"fmt"
	"strings"
)



type WPSInfo struct {
	bitmask   uint8  // Version (2 bits), ConfigMask (1), Lock (1), State (1), Registrar (1)
	presence  uint8

	passwordID    uint16
	configMethods uint16
	devTypeCat    uint16
	devTypeSub    uint16

	rfBands uint8

	serialNumber string
	manufacturer string
	modelName    string
	modelNumber  string
	deviceName   string
}



func (wi *WPSInfo) SetVersion(v uint8) {
	wi.bitmask &^= wpsVersionMask
	wi.bitmask  |= (v >> 4) & wpsVersionMask
}

func (wi *WPSInfo) Version() uint8 {
	return (wi.bitmask & wpsVersionMask)
}



func (wi *WPSInfo) SetConfig(configured bool) {
	if configured { wi.bitmask |= wpsConfigMask }
}

func (wi *WPSInfo) isConfigured() bool {
	return (wi.bitmask & wpsConfigMask) == wpsConfigMask
}



func (wi *WPSInfo) SetAPSetupLock(locked bool) {
	if locked { wi.bitmask |= wpsAPSetupLocked }
}

func (wi *WPSInfo) isLocked() bool {
	return (wi.bitmask & wpsAPSetupLocked) == wpsAPSetupLocked
}



func (wi *WPSInfo) SetStatePresence() {
	wi.bitmask |= wpsStatePresent
}

func (wi *WPSInfo) isStatePresent() bool {
	return (wi.bitmask & wpsStatePresent) == wpsStatePresent
}



func (wi *WPSInfo) SetRegistrar(selected bool) {
	if selected { wi.bitmask |= wpsSelectedRegistrar }
}

func (wi *WPSInfo) selectedRegistrar() bool {
	return (wi.bitmask & wpsSelectedRegistrar) == wpsSelectedRegistrar
}



func (wi *WPSInfo) SetPasswordID(v uint16) {
	wi.passwordID  = v
	wi.presence   |= 1 << passwordID
}

func (wi *WPSInfo) PasswordID() string {
	switch wi.passwordID {
	case passIDDefault    : return "PIN (default)"
	case passIDUserSpec   : return "PIN (user-specified)"
	case passIDMachine    : return "Machine"
	case passIDRekey      : return "Rekey"
	case passIDPushButton : return "Push Button"
	case passIDRegSpec    : return "Registrar-specified"
	default               : return fmt.Sprintf("Unknown (0x%04X)", wi.passwordID)
	}
}

func (wi *WPSInfo) HasPasswordID() bool {
	return (wi.presence & (1 << passwordID)) != 0
}



func (wi *WPSInfo) SetConfigMethods(m uint16) {
	wi.configMethods  = m
	wi.presence      |= 1 << configMethods
}

func (wi *WPSInfo) ConfigMethods() string {
	if wi.configMethods == 0 {
		return ""
	}

	var parts []string

	if wi.configMethods & configMethodUSBA       != 0 { parts = append(parts, "USB")         }
	if wi.configMethods & configMethodEthernet   != 0 { parts = append(parts, "Ethernet")    }
	if wi.configMethods & configMethodLabel      != 0 { parts = append(parts, "Label")       }
	if wi.configMethods & configMethodDisplay    != 0 { parts = append(parts, "Display")     }
	if wi.configMethods & configMethodExtNFC     != 0 { parts = append(parts, "NFC (ext)")   }
	if wi.configMethods & configMethodIntNFC     != 0 { parts = append(parts, "NFC (int)")   }
	if wi.configMethods & configMethodNFCIntf    != 0 { parts = append(parts, "NFC (intf)")  }
	if wi.configMethods & configMethodPushButton != 0 { parts = append(parts, "Push Button") }
	if wi.configMethods & configMethodKeypad     != 0 { parts = append(parts, "Keypad")      }

	return strings.Join(parts, ", ")
}

func (wi *WPSInfo) HasConfigMethods() bool {
	return (wi.presence & (1 << configMethods)) != 0
}



func (wi *WPSInfo) SetRFBands(b uint8) {
	wi.rfBands   = b
	wi.presence |= 1 << rfBands
}

func (wi *WPSInfo) RFBands() string {
	if wi.rfBands == 0 {
		return ""
	}

	var parts []string

	if wi.rfBands & rfBand24GHz != 0 { parts = append(parts, "2.4 GHz") }
	if wi.rfBands & rfBand5GHz  != 0 { parts = append(parts, "5 GHz")   }
	if wi.rfBands & rfBand60GHz != 0 { parts = append(parts, "60 GHz")  }

	return strings.Join(parts, " / ")
}

func (wi *WPSInfo) HasRFBands() bool {
	return (wi.presence & (1 << rfBands)) != 0
}



func (wi *WPSInfo) SetDeviceType(cat, sub uint16) {
	wi.devTypeCat  = cat
	wi.devTypeSub  = sub
	wi.presence   |= 1 << devType
}

func (wi *WPSInfo) DeviceType() string {
	cat := deviceCategoryName(wi.devTypeCat)
	
	if wi.devTypeSub == 0 {
		return cat
	}
	
	return cat + " / " + deviceSubcategoryName(wi.devTypeCat, wi.devTypeSub)
}

func (wi *WPSInfo) HasDeviceType() bool {
	return (wi.presence & (1 << devType)) != 0
}



func (wi *WPSInfo) SetManufacturer(s string) { wi.manufacturer = trimNull(s) }
func (wi *WPSInfo) Manufacturer() string     { return wi.manufacturer        }
func (wi *WPSInfo) HasManufacturer() bool    { return wi.manufacturer != ""  }

func (wi *WPSInfo) SetModelName(s string) { wi.modelName = trimNull(s) }
func (wi *WPSInfo) ModelName() string     { return wi.modelName        }
func (wi *WPSInfo) HasModelName() bool    { return wi.modelName != ""  }

func (wi *WPSInfo) SetModelNumber(s string) { wi.modelNumber = trimNull(s) }
func (wi *WPSInfo) ModelNumber() string     { return wi.modelNumber        }
func (wi *WPSInfo) HasModelNumber() bool    { return wi.modelNumber != ""  }

func (wi *WPSInfo) SetDeviceName(s string) { wi.deviceName = trimNull(s) }
func (wi *WPSInfo) DeviceName() string     { return wi.deviceName        }
func (wi *WPSInfo) HasDeviceName() bool    { return wi.deviceName != ""  }

func (wi *WPSInfo) SetSerialNumber(s string) { wi.serialNumber = trimNull(s) }
func (wi *WPSInfo) SerialNumber() string     { return wi.serialNumber        }
func (wi *WPSInfo) HasSerialNumber() bool    { return wi.serialNumber != ""  }



func trimNull(s string) string {
	return strings.TrimRight(s, "\x00")
}


func deviceCategoryName(cat uint16) string {
	switch cat {
	case 1  :  return "Computer"
	case 2  :  return "Input Device"
	case 3  :  return "Printer/Scanner/Fax"
	case 4  :  return "Camera"
	case 5  :  return "Storage"
	case 6  :  return "Network Infrastructure"
	case 7  :  return "Display"
	case 8  :  return "Multimedia"
	case 9  :  return "Gaming"
	case 10 : return "Telephone"
	case 11 : return "Audio"
	case 12 : return "Dock"
	case 13 : return "Other"
	default : return fmt.Sprintf("Unknown (%d)", cat)
	}
}



func deviceSubcategoryName(cat, sub uint16) string {
	if cat == 6 {
		switch sub {
		case 1 : return "AP"
		case 2 : return "Router"
		case 3 : return "Switch"
		case 4 : return "Gateway"
		case 5 : return "Bridge"
		}
	}
	return fmt.Sprintf("sub %d", sub)
}



func (wi *WPSInfo) MinimalString() string {
    if wi.Version() == 0 && !wi.isStatePresent() && !wi.isLocked() {
        return "0.0"
    }

    if wi.isLocked() {
        return "Locked"
    }

    var b strings.Builder

    b.WriteString(wi.formatVersion())

	if wi.selectedRegistrar() {
		b.WriteString(" RGT")
	}

    if wi.isStatePresent() {
        if wi.isConfigured() {
            b.WriteString(" CONF")
        } else {
            b.WriteString(" UNCONF")
        }
    }

    return b.String()
}



func (wi *WPSInfo) formatVersion() string {
	return fmt.Sprintf("%d.0", wi.Version())
}



func (wi *WPSInfo) Len() int {
	if wi.isLocked() {
        return 6
    }
   
	total := 3  // 0.0 or 1.0 or 2.0

	if wi.selectedRegistrar() {
		total += 4  // ' ' + RGT
	}

	if wi.isStatePresent() {
    	if wi.isConfigured() {
    	    total += 5  // ' ' + conf
    	} else {
    	    total += 7  // ' ' + unconf
    	}
	}

    return total
}