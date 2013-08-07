package main

import (
	"container/list"
	"crypto/sha256"
	"math/big"
)

type Participant struct {
	// participant number
	i int

	// long-term private key
	sk *big.Int
	// long-term public key (PUBLIC)
	pk *big.Int
	// conversation pid
	// (Set of participant identities (including our own identity))
	pid []byte

	// nonce
	k []byte
	// DH privkey
	x *big.Int
	// DH pubkey (PUBLIC @ round 1)
	y *big.Int
	// nonce commitment (PUBLIC @ round 1)
	h_k [sha256.Size]byte

	// sid (PUBLIC @ round 2)
	// (The sid can be thought of like the public part of session
	// key. It should represent a session key uniquely.)
	sid [sha256.Size]byte
	// Schnorr blind factor
	r *big.Int
	// Schnorr blind factor pubkey (PUBLIC @ round 2)
	z *big.Int

	// shared-secret with left participant
	t_l [sha256.Size]byte
	// shared-secret with right participant
	t_r [sha256.Size]byte
	// xored shared-secrets of adjacent participants (PUBLIC @ round 3)
	t [sha256.Size]byte
	// k^t_R (PUBLIC @ round 3)
	encrypted_commited_value [sha256.Size]byte

	// session key
	ss [sha256.Size]byte
	// session confirmation
	sconf [sha256.Size]byte
	// hash of session information (authenticated in the schnorr sig)
	c *big.Int
	// schnorr signature1 (PUBLIC @ round 4)
	d *big.Int
}

// Create a new participant with number 'participant_number'
func NewParticipant(participant_number int) *Participant {
	p := new(Participant)
	p.i = participant_number
	p.pid = []byte("XXXsomethingunique")

	// Generate long-term private/public keypair
	p.sk = rand_int(group_q)
	p.pk = new(big.Int).Exp(group_g, p.sk, group_p)

	debug.Printf("Created participant %d:\nsk = %x\npk = %x\n",
		p.i, p.sk, p.pk)

	return p
}

// Return the next element (after 'el') of a container/list. If 'el'
// is the last element, return the first one (like a circular list
// would have done).
func get_next_circular(el *list.Element) (*list.Element) {
	// found participant in list
	el_next := el.Next()
	if el_next == nil { // participant was the last in the list
		return participants.Front()
	}
	return el_next
}

// Return the previous element (before 'el') of a container/list. If
// 'el' is the first element, return the last one (like a circular
// list would have done).
func get_prev_circular(el *list.Element) (*list.Element) {
	// found participant in list
	el_prev := el.Prev()
	if el_prev == nil { // participant was the last in the list
		return participants.Back()
	}
	return el_prev
}

// Get list element of participant 'i'
func get_participant_element(i int) (*list.Element) {
	// Crawl the list of participants till you find 'i'
	for p_tmp := participants.Front(); p_tmp != nil ; p_tmp = p_tmp.Next() {
		if p_tmp.Value.(*Participant).i == i {
			return p_tmp
		}
	}

	panic("couldn't find participant")
}

// Given a participant, return the next participant in the list. If
// it's the last one, return the first one (like a circular list would
// have done).
func (p *Participant) get_next_participant_circular() (*list.Element) {
	p_tmp := get_participant_element(p.i)
	if p_tmp == nil {
		panic("next_circular: could not find participant")
	}

	// found participant in list
	p_next := p_tmp.Next()
	if p_next == nil { // participant was the last in the list
		return participants.Front()
	}
	return p_next
}

// Given a participant, return the previous participant in the
// list. If it's the first one, return the last one (like a circular
// list would have done).
func (p *Participant) get_prev_participant_circular() (*list.Element) {
	p_tmp := get_participant_element(p.i)
	if p_tmp == nil {
		panic("prev_circular: could not find participant")
	}

	// found participant in list
	p_prev := p_tmp.Prev()
	if p_prev == nil { // participant was the last in the list
		return participants.Back()
	}
	return p_prev
}
