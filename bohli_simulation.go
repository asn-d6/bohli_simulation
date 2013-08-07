package main

import (
	"crypto/sha256"
	"math/big"
	"fmt"
	"bytes"
	"container/list"
)


// XXX misc notes:
// are all array-to-slice operations correct?

// Crypto details:
// all DLP exponentiations happen (mod p)
// all schnorr signature operations happen (mod q)

const (
	// security_param is equal to the output length of SHA256
	security_param = 32 // 32 * 8 = 256

	// number of simulated participants
	n_participants = 3
	// XXX what happens if n_participants == 2?
)

var (
	// group order
	group_q *big.Int
	// group generator
	group_g *big.Int
	// group prime (??)
	group_p *big.Int
)

// linked list of participants
var participants list.List

// Round 1:
// Where each participant commits to her key share, and publicizes her
// circular group key agreement public key.
func (p *Participant) round_1() {
	var hashBytes [security_param]byte

	// Compute phase
	// k <- {0,1}^k
	p.k = rand_bytes(hashBytes[:])
	// x <- Z_q
	p.x = rand_int(group_q)
	// y = g^x
	p.y = new(big.Int).Exp(group_g, p.x, group_p)

	// Broadcast phase
	// Compute commitment
	h := sha256.New()
	h.Write(p.k)
	h.Sum(p.h_k[:0])
	// Broadcast it
	fmt.Printf("[M-1-%d BROADCAST START]\n", p.i)
	fmt.Printf("H(k_%d) = %x\ny_%d =  %d\n", p.i, p.h_k, p.i, p.y)
	fmt.Printf("[M-1-%d BROADCAST END]\n", p.i)

	// Print debugging info
	debug.Printf("Participant %d:\nk = 0x%x\nx = %d\ny = %d\nh_k = 0x%x",
		p.i, p.k, p.x, p.y, p.h_k)
}

// Round 2:
// Where each participant generates a session id, and publicizes her
// Schnorr short-term public key
func (p *Participant) round_2() {
	// Compute phase
	// sid = H(pid || H(k_1) || H(k_2)|| ... || H(k_n))
	h := sha256.New()
	h.Write(p.pid)
	for p_tmp := participants.Front(); p_tmp != nil; p_tmp = p_tmp.Next() {
		h.Write(p_tmp.Value.(*Participant).h_k[:])
	}
	h.Sum(p.sid[:0])

	// r <- Z_q
	p.r = rand_int(group_q)
	// z = g^r
	p.z = new(big.Int).Exp(group_g, p.r, group_p)

	debug.Printf("Participant %d:\nr = 0x%x\nz = 0x%x\n",
		p.i, p.r, p.z)

	// Broadcast phase
	fmt.Printf("[M-2-%d BROADCAST START]\n", p.i)
	fmt.Printf("sid_%d = 0x%x\nz_%d = 0x%x\n", p.i, p.sid, p.i, p.z)
	fmt.Printf("[M-2-%d BROADCAST END]\n", p.i)
}

// Round 3:
// Where each participant calculates the shared-secret for her
// neighbours and then publicizes her encrypted commited value.
func (p *Participant) round_3() {
	// Compute phase
	prev_p := p.get_prev_participant_circular().Value.(*Participant)
	next_p := p.get_next_participant_circular().Value.(*Participant)
	debug.Printf("%d. previous: %d. next: %d", p.i, prev_p.i, next_p.i)

	// XXX We use the big.Int.Bytes() method to turn a big.Int to raw bytes.
	// Bytes() returns the absolute value of hte int as a big-endian byte slice

	// t_L = H(y_{i-1}^x)
	h_l := sha256.New()
	to_hash_tmp_l := new(big.Int).Exp(prev_p.y, p.x, group_p)
	h_l.Write(to_hash_tmp_l.Bytes())
	h_l.Sum(p.t_l[:0])
	debug.Printf("prev_p.y = 0x%x\np.x = 0x%x\nto_hash_tmp_l = 0x%x\nt_L = 0x%x", prev_p.y, p.x, to_hash_tmp_l, p.t_l)

	// t_R = H(y_{i+1}^x)
	h_r := sha256.New()
	to_hash_tmp_r := new(big.Int).Exp(next_p.y, p.x, group_p)
	h_r.Write(to_hash_tmp_r.Bytes())
	h_r.Sum(p.t_r[:0])
	debug.Printf("next_p.y = 0x%x\np.x = 0x%x\nto_hash_tmp_r = 0x%xt_L = 0x%x", next_p.y, p.x, to_hash_tmp_r, p.t_r)

	// t = t_L ^ t_R
	xored_tmp := xor_bytes(p.t_l[:], p.t_r[:])
	copy(p.t[:], xored_tmp) // XXX Does it fit in p.t?
	debug.Printf("t_L = 0x%x\nt_R = 0x%x\nt = 0x%x", p.t_l, p.t_r, p.t)

	// Broadcast phase
	// broadcast (k ^ t_R, t, U_i)
	encrypted_commited_value := xor_bytes(p.k, p.t_r[:])
	copy(p.encrypted_commited_value[:], encrypted_commited_value)

	fmt.Printf("[M-3-%d BROADCAST START]\n", p.i)
	fmt.Printf("encrypted_commit = 0x%x, t = 0x%x\n", p.encrypted_commited_value, p.t)
	fmt.Printf("[M-3-%d BROADCAST END]\n", p.i)
}

// Verify that the round1 commitment of participant 'i' was legit.
// Return true if the commitment was legit; otherwise false.
// XXX need better explanation on how the circular decryption happens
func (p *Participant) commitment_was_legit(i int) (bool) {
	// If clockwise, to get k_i from the PoV of participant 'i-n':
	//     k_i ^ t_i^R ^ T_i ^ T_{i-1} ^ T_{i-2} ^ T_{i-n+1} ^ H(y_{i-n+1}^x{i-n})
	// Example:
	// to get k_5  from the PoV of 2:
	//     k_5 ^ t_5^R ^ T_5 ^ T_4 ^ T_3 ^ H(y_3^x_2)
	// Let's begin by finding participant 'i'

	// Get target participant
	p_target := get_participant_element(i)
	if p.i == p_target.Value.(*Participant).i {
		debug.Printf("Asked to verify our own commited value (k_%d): Trivially true.", p.i)
		return true
	}

	debug.Printf("[-] Computing k_%d from the PoV of %d:", p_target.Value.(*Participant).i, p.i)

	xor_list := make([][]byte, 0) // list that contains all the values that must be xored
	// add the encrypted k_d to the XOR list
	debug.Printf("Appending k_%d XOR t_%d^R: 0x%x.",
		p_target.Value.(*Participant).i, p_target.Value.(*Participant).i, p_target.Value.(*Participant).t[:])
	xor_list = append(xor_list, p_target.Value.(*Participant).encrypted_commited_value[:])
	p_tmp := p_target

	// Loop participants in a clockwise fashion
	for {
		if p_tmp.Value.(*Participant).i == p.i {
			// we got from participant 'i' to 'p'.
			// time to stop.
			debug.Printf("Reached %d. Bailing.", p_tmp.Value.(*Participant).i)
			break
		}

		if p_tmp.Value.(*Participant).i == ((p.i + 1) % n_participants ) {
			// append H(y_i^x_j)
			dh_shared_secret := new(big.Int).Exp(p_tmp.Value.(*Participant).y, p.x, group_p)
			h := sha256.New()
			h.Write(dh_shared_secret.Bytes())
			hashed_dh := h.Sum(nil)
			xor_list = append(xor_list, hashed_dh[:])
			debug.Printf("Appending H(y_%d^x_%d): 0x%x.", p_tmp.Value.(*Participant).i, p.i, hashed_dh[:])
		}

		// add T_j to the list
		xor_list = append(xor_list, p_tmp.Value.(*Participant).t[:])
		debug.Printf("Appending T_%d: 0x%x.", p_tmp.Value.(*Participant).i, p_tmp.Value.(*Participant).t[:])

		p_tmp = get_prev_circular(p_tmp)
	}

	// xor everything together
	xor_panic := xor_bytes(xor_list[0], xor_list[1:]...)

	if bytes.Equal(xor_panic, p_target.Value.(*Participant).k) {
		// commitment was legit
		debug.Printf("Found legit commitment k_%d: 0x%x", p_target.Value.(*Participant).i, xor_panic)
		return true
	}

	fmt.Printf("xor_panic k_%d: 0x%x", p_target.Value.(*Participant).i, xor_panic)
	fmt.Printf("for realz k_%d: 0x%x", p_target.Value.(*Participant).i, p_target.Value.(*Participant).k)
	return false
}

// Do the verify phase of round 4.
func (p *Participant) round4_verify() (bool) {
	// Verify that t_1 ^ t_2 ^ t_3 ^ ... ^ t_n = 0
	// XXX crappy code
	pre_xor := participants.Front().Value.(*Participant).t
	for p_tmp := participants.Front().Next() ; p_tmp != nil ; p_tmp = p_tmp.Next() {
		xor_step := xor_bytes(pre_xor[:], p_tmp.Value.(*Participant).t[:])
		copy(pre_xor[:], xor_step)
	}
	debug.Printf("[-] VERIFY that pre_xor is zeroes: pre_xor = 0x%x", pre_xor)
	// check that the final xor value is 0
	for i := range pre_xor {
		if pre_xor[i] != 0 {
			fmt.Println("My god! pre_xor: 0x%x", pre_xor)
			return false
		}
	}

	// for each participant, decrypt her k_j value (ciphertext
	// broadcasted in round3) and check that her round1 commitment
	// was legit:
	for i := 0; i < n_participants; i++ {
		result := p.commitment_was_legit(i)
		if !result {
			return false
		}
	}

	return true
}

// Round 4:
// Where each participant generates her sessionkey and session
// confirmation. Then they send a Schnorr signature to authenticate
// the hash of their session key and session confirmation.
func (p *Participant) round_4() {
	// Verify phase
	if !p.round4_verify() {
		panic("omg round4_verify failz")
	}

	// Compute phase
	// compute session key: sk_i = H(pid_i || k_i || ... || k_n)
	h_sk := sha256.New()
	h_sk.Write(p.pid)
	for p_tmp := participants.Front(); p_tmp != nil; p_tmp = p_tmp.Next() {
		h_sk.Write(p_tmp.Value.(*Participant).k[:])
	}
	h_sk.Sum(p.ss[:0])

	// compute session confirmation: sconf_i = H((y_i, k_i) || ... || (y_n, k_n))
	h_sconf := sha256.New()
	for p_tmp := participants.Front(); p_tmp != nil; p_tmp = p_tmp.Next() {
		h_sconf.Write(p_tmp.Value.(*Participant).y.Bytes())
		h_sconf.Write(p_tmp.Value.(*Participant).k[:])
	}
	h_sconf.Sum(p.sconf[:0])

	// compute c_i = H(sid_i || sconf_i) mod q
	h_ci := sha256.New()
	h_ci.Write(p.sid[:0])
	h_ci.Write(p.sconf[:0])
	p.c = new(big.Int).SetBytes(h_ci.Sum(nil))
	p.c.Mod(p.c, group_q)

	// d_i = r_i - c_i * a_i (mod q)
	tmp := new(big.Int).Mul(p.c, p.sk)
	tmp.Mod(tmp, group_q) // XXX is this necessary?
	tmp.Sub(p.r, tmp)
	tmp.Mod(tmp, group_q)
	if tmp.Sign() < 0 {
		tmp.Add(tmp, group_q)
	}
	p.d = tmp

	debug.Printf("sk_i = 0x%x\nsconf_i = 0x%x\nc_i = 0x%x\nd_i = 0x%x\n",
		p.ss, p.sconf, p.c.Bytes(), p.d.Bytes())

	// Broadcast phase
	// broadcast (d_i, U_i)
	fmt.Printf("[M-4-%d BROADCAST START]\n", p.i)
	fmt.Printf("d_i = 0x%x\n", p.d.Bytes())
	fmt.Printf("[M-4-%d BROADCAST END]\n", p.i)
}

// Final verification:
// Where each participant verifies the Schnorr signatures of the other
// participants.
func (p *Participant) final_verification() (bool) {
	// foreach participant we need to verify that:
	// g^d_j * PK_j^c_i == z_j (mod p)
	for p_tmp_element := participants.Front() ; p_tmp_element != nil ; p_tmp_element = p_tmp_element.Next() {
		p_tmp := p_tmp_element.Value.(*Participant)

		if p_tmp.i == p.i {
			debug.Printf("Trivial final verification of %d", p.i)
			continue
		}

		// build g^d_j
		left_hand_side := new(big.Int).Exp(group_g, p_tmp.d, group_p)
		// build PK_j ^ c_i
		left_hand_side_tmp := new(big.Int).Exp(p_tmp.pk, p.c, group_p)
		// build g^d_j * PK_j^c_i
		left_hand_side.Mul(left_hand_side, left_hand_side_tmp)
		left_hand_side.Mod(left_hand_side, group_p)

		right_hand_side := p_tmp.z

		if left_hand_side.Cmp(right_hand_side) != 0 {
			fmt.Printf("Final verification failure!\nleft_hand_side: 0x%x\nright_hand_side: 0x%x\n",
				left_hand_side, right_hand_side)
			// XXX return errors.new("blabla") ?
			return false
		}

		debug.Printf("Final verification (%d verifies %d) (g^d_%d*PK_%d^c_%d == z_%d): 0x%x\n",
			p.i, p_tmp.i, p_tmp.i, p_tmp.i, p.i, p_tmp.i, right_hand_side)
	}

	return true
}

func main() {
	fmt.Println("Bohli Deniable (M-<phase>-<participant>)")

	fmt.Println("[*] Initialization")

	// initialize simulation participants and put them in the linked
	// list
	for i := 0; i < n_participants; i++ {
		participants.PushBack(NewParticipant(i))
	}

	fmt.Println("[*] Round 1")

	// do round 1
	for p := participants.Front(); p != nil; p = p.Next() {
		p.Value.(*Participant).round_1()
	}

	fmt.Println("[*] Round 2")

	// do round 2
	for p := participants.Front(); p != nil; p = p.Next() {
		p.Value.(*Participant).round_2()
	}

	fmt.Println("[*] Round 3")

	// do round 3
	for p := participants.Front(); p != nil; p = p.Next() {
		p.Value.(*Participant).round_3()
	}

	fmt.Println("[*] Round 4")

	// do round 4
	for p := participants.Front(); p != nil; p = p.Next() {
		p.Value.(*Participant).round_4()
	}

	fmt.Println("[*] Final verification")

	// do final verification
	for p := participants.Front(); p != nil; p = p.Next() {
		if (!p.Value.(*Participant).final_verification()) {
			panic("final verification failed!")
		}
	}

	// Print results
	p := participants.Front().Value.(*Participant)
	fmt.Printf("[*] Final verification was correct! Finished!\n")
	fmt.Printf("[*] session_key = 0x%x\n", p.ss)
	fmt.Printf("[*] session_confirmation = 0x%x\n", p.sconf)
}

// initiate crypto parameters (called on startup)
func init() {
	// 2.1.  1024-bit MODP Group with 160-bit Prime Order Subgroup
	// from RFC5114
	// XXX change it to something more paranoid

	// group prime
	group_p, _ = new(big.Int).SetString("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
	// subgroup size
	group_q, _ = new(big.Int).SetString("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16)
	// generator
	group_g, _ = new(big.Int).SetString("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)
}

