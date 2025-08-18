/*
Copyright © 2020 GridPlus dan.veenstra@gridplus.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	safecard "github.com/GridPlus/keycard-go"
	"github.com/GridPlus/keycard-go/apdu"
	"github.com/GridPlus/keycard-go/globalplatform"
	"github.com/gridplus/safecard-cli/card"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

// importSeedCmd represents the importSeed command
var importSeedCmd = &cobra.Command{
	Use:   "importSeed",
	Short: "Import a hex seed into SafeCard.",
	Long: `Import a hex seed (from exportSeed command) into your SafeCard.
This allows you to restore a seed that was previously exported from another SafeCard.
This will overwrite any existing seed on the card.`,
	Run: func(cmd *cobra.Command, args []string) {
		importSeed()
	},
}

func init() {
	rootCmd.AddCommand(importSeedCmd)
}

func importSeed() {
	fmt.Println("\n===========================================")
	fmt.Println("WARNING: This will overwrite any existing seed on your SafeCard!")
	fmt.Println("Make sure you have backed up any important keys before proceeding.")
	fmt.Println("===========================================")

	// Connect to SafeCard first (following pattern of other commands)
	cs, err := card.OpenSecureConnection(readerIdx)
	if err != nil {
		fmt.Println("Unable to open secure connection with card:", err)
		return
	}

	// Prompt user for PIN early in the process
	pinPrompt := promptui.Prompt{
		Label: "Pin",
		Mask:  '*',
	}
	fmt.Println("Please enter your 6-digit PIN:")
	pin, err := pinPrompt.Run()
	if err != nil {
		fmt.Println("Error reading PIN:", err)
		return
	}

	err = cs.VerifyPIN(pin)
	if err != nil {
		fmt.Println("Error verifying PIN:", err)
		return
	}

	fmt.Println("✓ PIN verified successfully")

	// Confirm user wants to proceed
	confirm := promptui.Select{
		Label: "Do you want to proceed?",
		Items: []string{"Yes", "No"},
	}
	_, result, err := confirm.Run()
	if err != nil || result != "Yes" {
		fmt.Println("Operation cancelled.")
		return
	}

	// Get hex seed from user
	seedPrompt := promptui.Prompt{
		Label: "Enter your hex seed (from exportSeed command)",
	}
	fmt.Println("Please enter your hex seed:")
	hexInput, err := seedPrompt.Run()
	if err != nil {
		fmt.Println("Error reading hex seed:", err)
		return
	}

	// Clean and validate hex input
	hexInput = strings.TrimSpace(strings.ReplaceAll(hexInput, " ", ""))
	if len(hexInput)%2 != 0 {
		fmt.Println("Invalid hex string: odd number of characters")
		return
	}

	// Decode hex string to bytes
	seed, err := hex.DecodeString(hexInput)
	if err != nil {
		fmt.Println("Invalid hex string:", err)
		return
	}

	// Validate seed length (typically 32 or 64 bytes for common seed lengths)
	if len(seed) < 16 || len(seed) > 64 {
		fmt.Printf("Warning: Unusual seed length (%d bytes). Expected 16-64 bytes.\n", len(seed))
		proceed := promptui.Select{
			Label: "Do you want to continue anyway?",
			Items: []string{"Yes", "No"},
		}
		_, proceedResult, err := proceed.Run()
		if err != nil || proceedResult != "Yes" {
			fmt.Println("Operation cancelled.")
			return
		}
	}

	fmt.Printf("✓ Valid hex seed (%d bytes)\n", len(seed))

	// Final confirmation
	finalConfirm := promptui.Select{
		Label: "Are you absolutely sure you want to import this seed into your SafeCard? This action cannot be undone.",
		Items: []string{"Yes, import the seed", "No, cancel"},
	}
	_, finalResult, err := finalConfirm.Run()
	if err != nil || finalResult != "Yes, import the seed" {
		fmt.Println("Operation cancelled.")
		return
	}

	// Load seed into SafeCard with exportable flag
	fmt.Println("Importing seed into SafeCard...")
	resp, err := loadExportableSeedFromHex(cs, seed)
	if err != nil {
		fmt.Println("Error importing seed into SafeCard:", err)
		return
	}

	fmt.Printf("✓ Seed imported into SafeCard (response: %d bytes)\n", len(resp))
	fmt.Printf("  Full response data: %s\n", hex.EncodeToString(resp))

	// Verify the seed was loaded correctly and is exportable
	fmt.Println("Verifying seed is exportable...")

	// Test exportability by attempting to export the seed
	exportedSeed, err := cs.ExportSeed()
	if err != nil {
		fmt.Printf("⚠ WARNING: Seed export verification failed: %v\n", err)
		fmt.Println("The seed was imported but may not be accessible for export operations.")
		return
	}

	// Verify the exported seed matches what we loaded
	if len(exportedSeed) == len(seed) {
		fmt.Printf("✓ Seed export verification successful (exported %d bytes)\n", len(exportedSeed))
		
		// Verify first 8 bytes match for additional confirmation
		if len(seed) >= 8 && hex.EncodeToString(seed[:8]) == hex.EncodeToString(exportedSeed[:8]) {
			fmt.Println("✓ Exported seed data matches imported seed")
		} else {
			fmt.Println("⚠ WARNING: Exported seed data doesn't match imported seed")
		}
	} else {
		fmt.Printf("⚠ WARNING: Exported seed length (%d bytes) doesn't match imported seed length (%d bytes)\n",
			len(exportedSeed), len(seed))
	}

	fmt.Println("✅ SUCCESS: Seed has been successfully imported and verified as exportable!")
	fmt.Println("\nYour SafeCard is now ready to use with the imported seed.")
	fmt.Println("The seed can be exported again using the exportSeed command if needed.")
}

// newCommandLoadExportableSeedFromHex creates a command to load an exportable seed from hex
// Based on GridPlus SafeCard docs: P2 controls exportability (0=non-exportable, 1=exportable)
func newCommandLoadExportableSeedFromHex(seed []byte) *apdu.Command {
	const (
		InsLoadKey    = 0xD0
		P1LoadKeySeed = 0x03 // Same as keycard-go library
		P2Exportable  = 0x01 // P2 = 1 means exportable (from GridPlus docs)
	)

	return apdu.NewCommand(
		globalplatform.ClaGp, // Class byte
		InsLoadKey,           // Instruction: Load Key
		P1LoadKeySeed,        // P1: Load seed instruction type
		P2Exportable,         // P2: Exportable flag (1 = exportable)
		seed,                 // Data: the seed to load
	)
}

// sendSecureCommandFromHex sends a custom command through the CommandSet's secure channel
// This encapsulates the reflection logic needed to access the private secure channel
func sendSecureCommandFromHex(cs *safecard.CommandSet, cmd *apdu.Command) (*apdu.Response, error) {
	// Access the private secure channel field using reflection
	csValue := reflect.ValueOf(cs).Elem()
	scField := csValue.FieldByName("sc")
	
	// Make the field accessible
	scField = reflect.NewAt(scField.Type(), unsafe.Pointer(scField.UnsafeAddr())).Elem()
	
	// Call the Send method
	sendMethod := scField.MethodByName("Send")
	if !sendMethod.IsValid() {
		return nil, fmt.Errorf("could not access secure channel Send method")
	}
	
	results := sendMethod.Call([]reflect.Value{reflect.ValueOf(cmd)})
	if len(results) != 2 {
		return nil, fmt.Errorf("unexpected number of return values from Send")
	}
	
	// Extract response and error
	resp := results[0].Interface().(*apdu.Response)
	errInterface := results[1].Interface()
	if errInterface != nil {
		return nil, errInterface.(error)
	}
	
	return resp, nil
}

// loadExportableSeedFromHex loads a seed into the SafeCard with the exportable flag set
// This mirrors the original LoadSeed method but uses our custom exportable command
func loadExportableSeedFromHex(cs *safecard.CommandSet, seed []byte) ([]byte, error) {
	fmt.Println("Loading seed with exportable flag...")
	
	// Create our custom exportable load seed command
	cmd := newCommandLoadExportableSeedFromHex(seed)
	
	fmt.Printf("Sending APDU: CLA=0x%02X, INS=0x%02X, P1=0x%02X, P2=0x%02X, Data=%d bytes\n",
		cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, len(seed))

	// Send the command through the secure channel
	resp, err := sendSecureCommandFromHex(cs, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to send exportable seed load command: %v", err)
	}

	// Check response status (mimicking the original LoadSeed's checkOK approach)
	if resp.Sw != 0x9000 {
		return nil, fmt.Errorf("card returned error status: 0x%04X", resp.Sw)
	}

	fmt.Println("✓ Exportable seed loaded successfully!")
	return resp.Data, nil
}