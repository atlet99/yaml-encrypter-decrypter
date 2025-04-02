package processor

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
	"yaml-encrypter-decrypter/pkg/encryption"

	"github.com/expr-lang/expr"
	"gopkg.in/yaml.v3"
)

const AES = "AES256:" // Prefix for encrypted values

type Rule struct {
	Path      string
	Condition string
}

func debugLog(debug bool, format string, v ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func ProcessFile(filename, key, operation string, dryRun, debug bool) error {
	// Load encryption rules
	rules, err := loadRules(".yed_config.yml")
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	// Read YAML file
	data, err := readYAML(filename)
	if err != nil {
		return fmt.Errorf("error reading YAML file: %w", err)
	}

	if data == nil || len(data.Content) == 0 {
		return fmt.Errorf("invalid YAML structure: empty document")
	}

	// Process YAML file
	start := time.Now()
	processedPaths := make(map[string]bool)

	for _, rule := range rules {
		debugLog(debug, "Applying rule: Path='%s', Condition='%s'", rule.Path, rule.Condition)
		err := processYAML(data.Content[0], key, operation, rule, "", processedPaths, debug)
		if err != nil {
			return fmt.Errorf("error processing YAML with rule %v: %w", rule, err)
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
			return fmt.Errorf("error encoding YAML: %w", err)
		}
		fmt.Println(output.String())
	} else {
		// Write the updated YAML back to the file
		if err := writeYAML(filename, data); err != nil {
			return fmt.Errorf("error writing YAML file: %w", err)
		}
		fmt.Printf("File %s updated successfully.\n", filename)
	}

	return nil
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

func processYAML(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return fmt.Errorf("nil node encountered at path: %s", currentPath)
	}

	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("invalid mapping node at path %s: odd number of elements", currentPath)
		}

		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			if keyNode == nil || valueNode == nil {
				return fmt.Errorf("nil key or value node at path %s", currentPath)
			}

			newPath := strings.TrimPrefix(currentPath+"."+keyNode.Value, ".")

			// Skip already processed paths
			if processedPaths[newPath] {
				debugLog(debug, "Skipping already processed path: %s", newPath)
				continue
			}

			if valueNode.Kind == yaml.ScalarNode {
				// Apply rule
				if matchesRule(newPath, rule) && evaluateCondition(keyNode.Value, valueNode.Value, rule.Condition) {
					if operation == "encrypt" && !strings.HasPrefix(valueNode.Value, AES) {
						encryptedValue, err := encryption.Encrypt(key, valueNode.Value)
						if err != nil {
							return fmt.Errorf("failed to encrypt value for key '%s': %w", keyNode.Value, err)
						}
						debugLog(debug, "Encrypting key '%s': %s -> %s", keyNode.Value, valueNode.Value, AES+encryptedValue)
						valueNode.Value = AES + encryptedValue
						valueNode.Tag = "!!str"
						processedPaths[newPath] = true
					} else if operation == "decrypt" && strings.HasPrefix(valueNode.Value, AES) {
						decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(valueNode.Value, AES))
						if err != nil {
							return fmt.Errorf("failed to decrypt value for key '%s': %w", keyNode.Value, err)
						}
						debugLog(debug, "Decrypting key '%s': %s -> %s", keyNode.Value, valueNode.Value, decryptedValue)
						valueNode.Value = decryptedValue
						valueNode.Tag = "!!str"
						processedPaths[newPath] = true
					}
				}
			} else if valueNode.Kind == yaml.MappingNode {
				// Recursive processing
				if err := processYAML(valueNode, key, operation, rule, newPath, processedPaths, debug); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func evaluateCondition(key, value, condition string) bool {
	if condition == "" {
		return true
	}

	// Handle wildcard conditions
	if strings.Contains(condition, "*") {
		regex := "^" + strings.ReplaceAll(regexp.QuoteMeta(condition), "\\*", ".*") + "$"
		matched, err := regexp.MatchString(regex, value)
		if err != nil {
			log.Printf("Error processing regex condition '%s': %v", regex, err)
			return false
		}
		return matched
	}

	// Use expr for complex conditions
	program, err := expr.Compile(condition, expr.Env(map[string]interface{}{
		"key":   key,
		"value": value,
	}))
	if err != nil {
		log.Printf("Invalid condition: %s", err)
		return false
	}

	result, err := expr.Run(program, map[string]interface{}{
		"key":   key,
		"value": value,
	})
	if err != nil {
		log.Printf("Error evaluating condition '%s': %v", condition, err)
		return false
	}

	boolResult, ok := result.(bool)
	if !ok {
		log.Printf("Condition '%s' did not return a boolean result", condition)
		return false
	}
	return boolResult
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
