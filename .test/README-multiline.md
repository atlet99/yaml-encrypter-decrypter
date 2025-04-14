# YAML Multiline Support

This feature adds support for encrypting and decrypting multiline values in YAML files. The implementation handles different YAML multiline styles and preserves their formatting during encryption and decryption operations.

## Supported Multiline Formats

The following YAML multiline formats are supported:

### 1. Literal Style (|)

```yaml
key: |
  This is a literal multiline
  that preserves line breaks
  exactly as they are written.
```

### 2. Folded Style (>)

```yaml
key: >
  This is a folded multiline
  that will be rendered as a single
  line with spaces between.
```

### 3. PEM Certificates and Keys

Both styles of PEM representation are supported:

#### Single-line with Escaped Newlines

```yaml
private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvgIB...linebreaks...JlnNb\n-----END PRIVATE KEY-----"
```

#### Multiline Literal

```yaml
certificate: |
  -----BEGIN CERTIFICATE-----
  MIIFtTCCA52gA...
  multiple lines...
  Lr0xBLBGCJDDJv2a1q7y2WdgRNjfQc7VuQ+I
  -----END CERTIFICATE-----
```

## Implementation Details

The multiline support is implemented through a new set of functions in the processor package:

1. `DetectMultilineStyle`: Determines the multiline style of a YAML node (Literal, Folded, or Not Multiline)
2. `EncryptMultiline`: Encrypts a multiline scalar node while preserving its style information
3. `DecryptMultiline`: Decrypts a previously encrypted multiline node and restores appropriate style
4. `ProcessMultilineNode`: Main entry point for handling multiline nodes during processing
5. `IsMultilineContent`: Helper function to determine if a string contains multiline content

Key implementation features:

- Content detection using both explicit YAML style indicators and content analysis
- Special handling for PEM-formatted content with BEGIN/END markers
- Smart style restoration based on content characteristics
- Format preservation for both encryption and decryption operations
- Seamless integration with existing encryption/decryption workflows

## How It Works

1. When encrypting, the tool detects multiline values by:
   - Checking the YAML node style (literal or folded)
   - Looking for newlines in the content
   - Recognizing PEM-like formats with BEGIN/END markers

2. When encrypting multiline content:
   - The multiline content is encrypted as a single value
   - The original style information is internally preserved in the processing
   - The encrypted output is stored with appropriate YAML formatting

3. When decrypting:
   - Content detected as multiline (with newlines) will be restored with appropriate style
   - PEM certificates and keys are automatically formatted with literal style
   - Other multiline content uses appropriate style based on content characteristics
   - Strings with escaped newlines are preserved in their original format

## Usage Example

Encrypt a YAML file with multiline values:

```bash
bin/yed --file config.yaml --key "your-secure-key" --operation encrypt
```

Decrypt the file:

```bash
bin/yed --file config.yaml --key "your-secure-key" --operation decrypt
```

## Testing

You can test the multiline functionality with the provided test files:

```bash
# Test with regular multilines
cp .test/multiline-test.yml .test/test-multiline.yml
bin/yed --file .test/test-multiline.yml --key "your-secure-key" --operation encrypt
bin/yed --file .test/test-multiline.yml --key "your-secure-key" --operation decrypt

# Test with PEM keys in different formats
cp .test/pem-test.yml .test/test-pem.yml
bin/yed --file .test/test-pem.yml --key "your-secure-key" --operation encrypt
bin/yed --file .test/test-pem.yml --key "your-secure-key" --operation decrypt

# Test with SSH keys
cp .test/ssh-key-test.yml .test/test-ssh.yml 
bin/yed --file .test/test-ssh.yml --key "your-secure-key" --operation encrypt
bin/yed --file .test/test-ssh.yml --key "your-secure-key" --operation decrypt
```

## Example Configuration

To encrypt multiline values, include appropriate patterns in your `.yed_config.yml`:

```yaml
encryption:
  rules:
    - name: "password_rule"
      block: "smart_config.auth"
      pattern: "password"
      description: "Encrypt password field"
    - name: "private_key_rule"
      block: "secrets"
      pattern: "private_key"
      description: "Encrypt private key"
    - name: "certificate_rule"
      block: "credentials"
      pattern: "certificate"
      description: "Encrypt certificate"
```

No special configuration is needed for multiline handling - the tool automatically detects and preserves multiline formats. 