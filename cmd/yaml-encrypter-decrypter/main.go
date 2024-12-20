package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"yaml-encrypter-decrypter/pkg/encryption"

	"github.com/awnumar/memguard"
	"gopkg.in/yaml.v3"
)

const AES = "AES256:" // Prefix for encrypted values

var debug bool

type Rule struct {
	Path      string
	Condition string
}

func init() {
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	memguard.CatchInterrupt() // Handle interrupt signals securely
}

func debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func main() {
	defer memguard.Purge() // Purge sensitive data when the program exits

	// Command-line flags
	flagFile := flag.String("filename", "", "YAML file to encode/decode")
	flagOperation := flag.String("operation", "", "Available operations: encrypt, decrypt")
	flagDryRun := flag.Bool("dry-run", false, "Output only, no file changes")

	flag.Parse()

	if *flagFile == "" || *flagOperation == "" {
		log.Fatal("Please specify --filename and --operation (encrypt or decrypt)")
	}

	// Load encryption key securely
	encryptionKey := memguard.NewBufferFromBytes([]byte("your-encryption-key")) // Replace with secure loading
	defer encryptionKey.Destroy()

	// Load encryption rules
	rules, err := loadRules(".yed_config.yml")
	if err != nil {
		log.Fatalf("Error loading rules: %v", err)
	}

	// Process YAML file
	globalState := make(map[string]bool)
	processYamlFile(*flagFile, string(encryptionKey.Bytes()), *flagOperation, *flagDryRun, rules, globalState)
}

func loadRules(configFile string) ([]Rule, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var config struct {
		Encryption struct {
			EnvBlocks []string `yaml:"env_blocks"`
		} `yaml:"encryption"`
	}

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %w", err)
	}

	var rules []Rule
	for _, block := range config.Encryption.EnvBlocks {
		parts := strings.SplitN(block, " if ", 2)
		rule := Rule{
			Path:      parts[0],
			Condition: "",
		}
		if len(parts) == 2 {
			rule.Condition = parts[1]
		}
		rules = append(rules, rule)
	}
	debugLog("Loaded rules: %+v", rules)
	return rules, nil
}

func readYAML(filename string) (*yaml.Node, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var data yaml.Node
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %w", err)
	}
	return &data, nil
}

func writeYAML(filename string, data *yaml.Node) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}
	return nil
}

func processYamlFile(filename, key, operation string, dryRun bool, rules []Rule, globalState map[string]bool) {
	start := time.Now()

	// Read the YAML file
	data, err := readYAML(filename)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	// Process the YAML
	err = processYAML(data.Content[0], key, operation, rules, "", globalState)
	if err != nil {
		log.Fatalf("Error processing YAML: %v", err)
	}

	// Output results
	elapsed := time.Since(start)
	fmt.Printf("YAML processing completed in %v\n", elapsed)

	if dryRun {
		// Dry-run mode: print the resulting YAML
		fmt.Println("Dry-run mode: The following changes would be applied:")
		output := &strings.Builder{}
		encoder := yaml.NewEncoder(output)
		encoder.SetIndent(2)
		if err := encoder.Encode(data); err != nil {
			log.Fatalf("Error encoding YAML: %v", err)
		}
		fmt.Println(output.String())
	} else {
		// Write the updated YAML back to the file
		if err := writeYAML(filename, data); err != nil {
			log.Fatalf("Error writing YAML file: %v", err)
		}
		fmt.Printf("File %s updated successfully.\n", filename)
	}
}

func processYAML(node *yaml.Node, key, operation string, rules []Rule, currentPath string, globalState map[string]bool) error {
	debugLog("Node kind: %d, Content: %+v, Path: %s", node.Kind, node.Content, currentPath)

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			newPath := strings.TrimPrefix(currentPath+"."+keyNode.Value, ".")

			// Recurse into nested mappings
			if valueNode.Kind == yaml.MappingNode {
				if err := processYAML(valueNode, key, operation, rules, newPath, globalState); err != nil {
					return err
				}
			} else if valueNode.Kind == yaml.ScalarNode {
				// Evaluate rules in order of priority
				for _, rule := range rules {
					if matchesRule(newPath, rule) {
						if evaluateConditionWithGlobalState(keyNode.Value, valueNode.Value, rule.Condition, globalState) {
							if operation == "encrypt" && !strings.HasPrefix(valueNode.Value, AES) {
								encryptedValue, err := encryption.Encrypt(key, valueNode.Value)
								if err != nil {
									return err
								}
								debugLog("Encrypting value for key '%s': %s -> %s", keyNode.Value, valueNode.Value, AES+encryptedValue)
								valueNode.Value = AES + encryptedValue
								valueNode.Tag = "!!str"
								break
							} else if operation == "decrypt" && strings.HasPrefix(valueNode.Value, AES) {
								decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(valueNode.Value, AES))
								if err != nil {
									return err
								}
								debugLog("Decrypting value for key '%s': %s -> %s", keyNode.Value, valueNode.Value, decryptedValue)
								valueNode.Value = decryptedValue
								valueNode.Tag = "!!str"
								break
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func evaluateConditionWithGlobalState(key string, value string, condition string, globalState map[string]bool) bool {
	conditions := strings.Fields(condition)

	for _, part := range conditions {
		switch strings.ToLower(part) {
		case "and":
			continue
		case "or":
			if globalState["orMet"] {
				return false
			}
		default:
			if strings.Contains(part, "==") {
				parts := strings.Split(part, "==")
				if len(parts) == 2 {
					conditionKey := strings.TrimSpace(parts[0])
					conditionValue := strings.TrimSpace(parts[1])

					match := conditionKey == key &&
						((strings.HasSuffix(conditionValue, "*") && strings.HasPrefix(value, strings.TrimSuffix(conditionValue, "*"))) ||
							(strings.HasPrefix(conditionValue, "*") && strings.HasSuffix(value, strings.TrimPrefix(conditionValue, "*"))) ||
							(strings.Contains(conditionValue, "*") && strings.Contains(value, strings.Trim(conditionValue, "*"))) ||
							value == conditionValue)

					if match {
						globalState["orMet"] = true
						return true
					}
				}
				continue
			}

			match := (strings.HasSuffix(part, "*") && strings.HasPrefix(key, strings.TrimSuffix(part, "*"))) ||
				(strings.HasPrefix(part, "*") && strings.HasSuffix(key, strings.TrimPrefix(part, "*"))) ||
				(strings.Contains(part, "*") && strings.Contains(key, strings.Trim(part, "*"))) ||
				key == part

			if match {
				globalState["orMet"] = true
				return true
			}
		}
	}
	return false
}

func matchesRule(path string, rule Rule) bool {
	normalizedPath := strings.TrimPrefix(path, ".")
	if rule.Path == "*" {
		return true
	}
	if strings.HasSuffix(rule.Path, ".*") || strings.HasSuffix(rule.Path, "*") {
		prefix := strings.TrimSuffix(rule.Path, "*")
		return strings.HasPrefix(normalizedPath, prefix)
	}
	return normalizedPath == rule.Path
}

func encryptBlock(node *yaml.Node, key, operation string) error {
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if valueNode.Kind == yaml.ScalarNode {
			valueStr := valueNode.Value
			if operation == "encrypt" && !strings.HasPrefix(valueStr, AES) {
				encryptedValue, err := encryption.Encrypt(key, valueStr)
				if err != nil {
					return fmt.Errorf("failed to encrypt value for key %s: %w", keyNode.Value, err)
				}
				valueNode.Value = AES + encryptedValue
				valueNode.Tag = "!!str"
			} else if operation == "decrypt" && strings.HasPrefix(valueStr, AES) {
				decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(valueStr, AES))
				if err != nil {
					return fmt.Errorf("failed to decrypt value for key %s: %w", keyNode.Value, err)
				}
				valueNode.Value = decryptedValue
				valueNode.Tag = "!!str"
			}
		} else if valueNode.Kind == yaml.MappingNode {
			if err := encryptBlock(valueNode, key, operation); err != nil {
				return err
			}
		}
	}
	return nil
}
