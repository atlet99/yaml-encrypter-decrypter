package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
	"yaml-encrypter-decrypter/pkg/encryption"

	"github.com/Knetic/govaluate"
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
	processYamlFile(*flagFile, string(encryptionKey.Bytes()), *flagOperation, *flagDryRun, rules)
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

func processYamlFile(filename, key, operation string, dryRun bool, rules []Rule) {
	start := time.Now()

	// Read the YAML file
	data, err := readYAML(filename)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	// Map to track already processed paths
	processedPaths := make(map[string]bool)

	// Apply rules in the order of priority
	for _, rule := range rules {
		debugLog("Applying rule: Path='%s', Condition='%s'", rule.Path, rule.Condition)
		err := processYAML(data.Content[0], key, operation, rule, "", processedPaths)
		if err != nil {
			log.Fatalf("Error processing YAML with rule %v: %v", rule, err)
		}
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

func processYAML(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			newPath := strings.TrimPrefix(currentPath+"."+keyNode.Value, ".")

			// Skip already processed paths
			if processedPaths[newPath] {
				debugLog("Skipping already processed path: %s", newPath)
				continue
			}

			if valueNode.Kind == yaml.ScalarNode {
				// Apply rule
				if matchesRule(newPath, rule) && evaluateCondition(keyNode.Value, valueNode.Value, rule.Condition) {
					if operation == "encrypt" && !strings.HasPrefix(valueNode.Value, AES) {
						encryptedValue, err := encryption.Encrypt(key, valueNode.Value)
						if err != nil {
							return fmt.Errorf("failed to encrypt value for key '%s': %v", keyNode.Value, err)
						}
						debugLog("Encrypting key '%s': %s -> %s", keyNode.Value, valueNode.Value, AES+encryptedValue)
						valueNode.Value = AES + encryptedValue
						valueNode.Tag = "!!str"
						processedPaths[newPath] = true
					} else if operation == "decrypt" && strings.HasPrefix(valueNode.Value, AES) {
						decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(valueNode.Value, AES))
						if err != nil {
							return fmt.Errorf("failed to decrypt value for key '%s': %v", keyNode.Value, err)
						}
						debugLog("Decrypting key '%s': %s -> %s", keyNode.Value, valueNode.Value, decryptedValue)
						valueNode.Value = decryptedValue
						valueNode.Tag = "!!str"
						processedPaths[newPath] = true
					}
				}
			} else if valueNode.Kind == yaml.MappingNode {
				// Recursive processing
				if err := processYAML(valueNode, key, operation, rule, newPath, processedPaths); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func evaluateCondition(key, value, condition string) bool {
	debugLog("Evaluating condition: key='%s', value='%s', condition='%s'", key, value, condition)

	if condition == "" {
		return true
	}

	// Replace wildcard (*) in conditions with regex patterns
	condition = strings.ReplaceAll(condition, "*", ".*")

	expression, err := govaluate.NewEvaluableExpression(condition)
	if err != nil {
		log.Printf("Invalid condition: %s", err)
		return false
	}

	parameters := map[string]interface{}{
		"key":   key,
		"value": value,
	}

	result, err := expression.Evaluate(parameters)
	if err != nil {
		log.Printf("Error evaluating condition: %s", err)
		return false
	}

	return result.(bool)
}

func matchesRule(path string, rule Rule) bool {
	if rule.Path == "*" {
		return true // Match all paths
	}

	// Convert wildcard patterns to regex
	pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(rule.Path), "\\*", ".*") + "$"
	matched, _ := regexp.MatchString(pattern, path)

	return matched
}
