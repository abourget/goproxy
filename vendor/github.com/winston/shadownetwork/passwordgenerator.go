package shadownetwork

import (
	"time"
	"sort"
	"math/rand"
	//"fmt"
	//"sync"
)


// Returns the most recent password
func (sn *ShadowNetwork) CurrentPassword() *Password {

	sn.passwordmu.Lock()
	defer sn.passwordmu.Unlock()

	//fmt.Printf("[DEBUG] CurrentPassword() - %+v \n", sn.Passwords)
	if sn.Passwords == nil {
		sn.Passwords = make([]Password, 0)
	}

	//fmt.Printf("  *** CurrentPassword() server password: %s\n", sn.Password)
	if len(sn.Passwords) == 0 || sn.NeedsNewPasswordWithoutLock() {
		//if len(sn.Password) > 0 {
		//	fmt.Println("[DEBUG] Adding new password with one year expiration")
		//	// If there's a hard-coded password, add it to the Passwords collection and give it a far out expiration date. This should only be used for testing.
		//	p := Password{
		//		Password:	sn.Password,
		//		NotBefore:	time.Now().Local(),
		//		NotAfter:	time.Now().Local().AddDate(1, 0, 0),
		//	}
		//
		//	sn.Passwords = append(sn.Passwords, p)
		//	//fmt.Printf("  *** CurrentPassword() - appended hard-coded password.\n")
		//} else {
		//	fmt.Printf("[DEBUG] CurrentPassword() - generating new password.\n")
			sn.GenerateNewPasswordWithoutLock()
			//fmt.Printf("[DEBUG] CurrentPassword() after generating new one - %+v \n", sn.Passwords)
		//}
	}

	return sn.currentPasswordWithoutLock()
}

// Gets the next password.
func (sn *ShadowNetwork) nextPasswordWithoutLock() *Password {

	if len(sn.Passwords) == 0 {
		return nil
	}

	cur := sn.currentPasswordWithoutLock()

	if cur == nil {
		// Sort passwords by earliest NotBefore
		sort.Slice(sn.Passwords[:], func(i,j int) bool {
			return sn.Passwords[i].NotBefore.Before(sn.Passwords[j].NotBefore)
		})

		return &sn.Passwords[0]
	}

	// Find the earliest password where NotBefore comes after our current NotAfter
	// Sort passwords by earliest NotBefore
	sort.Slice(sn.Passwords[:], func(i,j int) bool {
		return sn.Passwords[i].NotBefore.Before(sn.Passwords[j].NotBefore)
	})

	notafter := cur.NotAfter

	for _, p := range sn.Passwords {
		if p.NotBefore == notafter || p.NotBefore.After(notafter) {
			return &p
		}
	}

	return nil
}


// Helper function - returns password which is currently active. Caller must provide lock.
func (sn *ShadowNetwork) currentPasswordWithoutLock() *Password {
	for _, p := range sn.Passwords {
		if p.NotBefore.Before(time.Now().Local()) && p.NotAfter.After(time.Now().Local()) {
			//fmt.Printf("Returning this one...\n")
			return &p
		} /*else {
			fmt.Println("[DEBUG] Password not used. Now", time.Now().Local(), "Before", p.NotBefore, "After", p.NotAfter)
		}*/
	}

	return nil
}

func (sn *ShadowNetwork) RemoveExpiredPasswords() {

	sn.passwordmu.Lock()
	defer sn.passwordmu.Unlock()

	passwords := make([]Password, 0)

	for _, p := range sn.Passwords {
		//fmt.Printf("Remove password check: %v\n", p)
		if !p.NotAfter.Before(time.Now().Local()) {
			//fmt.Printf("Adding to list...\n")
			passwords = append(passwords, p)
		}
	}

	sn.Passwords = passwords
}

// Caller must lock
func (sn *ShadowNetwork) GetLatestNotAfterWithoutLock() (time.Time, bool) {

	if len(sn.Passwords) == 0 {
		return time.Now().Local(), false
	}

	sort.Slice(sn.Passwords[:], func(i,j int) bool {
		return sn.Passwords[i].NotAfter.After(sn.Passwords[j].NotAfter)
	})

	return sn.Passwords[0].NotAfter, true
}

// Returns true if there are no passwords which cover the time period 65 (60 seconds for loop + 5 extra) seconds from now
// Caller is responsible for lock
func (sn *ShadowNetwork) NeedsNewPasswordWithoutLock() bool {
	if len(sn.Passwords) == 0 {
		return true
	}

	comparetime := time.Now().Local().Add(time.Second * 65)

	for _, p := range sn.Passwords {
		if p.NotBefore.Before(comparetime) && p.NotAfter.After(comparetime) {
			return false
		}
	}

	/*for _, k := range sn.Passwords {
		if k.Created.After(time.Now().Local().Add(time.Minute * time.Duration(-sn.PasswordExpirationMinutes) )) {
			return false
		}
	}*/

	return true
}

// Adds a new password to the password list. Caller must lock.
func (sn *ShadowNetwork) GenerateNewPasswordWithoutLock() (Password) {

	//fmt.Printf("[DEBUG] GenerateNewPasswordWithoutLock()...\n")

	notbefore, _ := sn.GetLatestNotAfterWithoutLock()

	// If the latest password is expired, then the new password should become active now
	if (notbefore.Before(time.Now().Local())) {
		notbefore = time.Now().Local()
	}

	notafter := notbefore.Add(time.Minute * time.Duration(sn.PasswordExpirationMinutes))

	// If we don't currently have a password, then we have to create one to fill the gap
	current := sn.currentPasswordWithoutLock()
	if current == nil {
		notbefore = time.Now().Local()

		// TODO: If there a password starting in the future, then make sure we don't overlap.
		// This is technically only necessary for testing as we will never delete current passwords or
		// alter their NotBefore/NotAfter settings.

		notafter = notbefore.Add(time.Minute * time.Duration(sn.PasswordExpirationMinutes))
	}

	//fmt.Printf("GenerateNewPassword: %v\n", last)

	// TODO: Should set the NotBefore date to equal the last NotAfter date
	p := Password{
		Password:	sn.generateRandomPassword(12),
		NotBefore:	notbefore,
		NotAfter:	notafter,
	}

	//fmt.Printf("[DEBUG] GenerateNewPassword - new password: %v\n", p)

	sn.Passwords = append(sn.Passwords, p)
	return p
}

var charRunes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func (sn *ShadowNetwork) generateRandomPassword(length int) (string) {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, length)
	for i := range b {
		b[i] = charRunes[rand.Intn(len(charRunes))]
	}
	return string(b)
}

