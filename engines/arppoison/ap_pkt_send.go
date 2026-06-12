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

package arppoison

import (
	"offscan/internal/packet/builder"
	"offscan/internal/sockets"
)



func (ap *arpPoison) startPoisoner() {
	ap.wg.Add(1)
	go func() {
		defer ap.wg.Done()
		ap.initPoisoningTools()
		ap.sendPoisoningPkts()
	}()
}



func (ap *arpPoison) initPoisoningTools() {
	ap.socket  = sockets.NewL2Socket(&ap.iface)
	ap.builder = builder.NewArpPkt()
	ap.builder.SetOpcode(builder.ArpReqCode)
}



func (ap *arpPoison) sendPoisoningPkts() {
	for {
		select{
		case <-ap.ctx.Done():
			return

		default:
			ap.sendPkt()
		}
	}
}



func (ap *arpPoison) sendPkt() {

}