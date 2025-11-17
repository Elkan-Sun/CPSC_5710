import os
import re
import glob
import subprocess

class DiscordSecurityScanner:
    def __init__(self):
        # Patterns that security tools might use
        self.token_patterns = {
            'user_token': r'[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27}',
            'mfa_token': r'mfa\.[a-zA-Z0-9_-]{84}',
            'bot_token': r'[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27}'
        }
        
        # Expanded Discord paths to check on macOS
        self.discord_paths = [
            os.path.expanduser("~/Library/Application Support/discord"),
            os.path.expanduser("~/Library/Application Support/discordcanary"),
            os.path.expanduser("~/Library/Application Support/discordptb"),
            os.path.expanduser("~/Applications/Discord.app"),
            os.path.expanduser("/Applications/Discord.app"),
            os.path.expanduser("~/Applications/Discord Canary.app"),
            os.path.expanduser("/Applications/Discord Canary.app")
        ]

    def find_discord_installations(self):
        """Try to find Discord installations using multiple methods"""
        print("🔍 Searching for Discord installations...")
        
        found_installations = []
        
        for path in self.discord_paths:
            if os.path.exists(path):
                found_installations.append(path)
                print(f"✅ Found: {path}")
        
        try:
            result = subprocess.run(['mdfind', 'kMDItemKind=="Application" && kMDItemDisplayName=="Discord"'], 
                                  capture_output=True, text=True)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line and line not in found_installations:
                        found_installations.append(line)
                        print(f"✅ Found via Spotlight: {line}")
        except:
            pass
        
        user_apps = glob.glob(os.path.expanduser("~/Applications/*Discord*"))
        for app in user_apps:
            if app not in found_installations:
                found_installations.append(app)
                print(f"✅ Found in Applications: {app}")
        
        if not found_installations:
            print("❌ No Discord installations found in standard locations")
            
        return found_installations

    def check_discord_path_permissions(self):
        """Check if Discord directories have secure permissions"""
        print("🔍 Checking Discord Directory Permissions...")
        
        found_installations = self.find_discord_installations()
        results = []
        
        if not found_installations:
            results.append("❌ No Discord installations detected")
            return results
        
        for installation in found_installations:
            if os.path.exists(installation):
                try:
                    stat = os.stat(installation)
                    permissions = oct(stat.st_mode)[-3:]
                    permission_analysis = self.analyze_permissions(permissions)
                    results.append(f"📁 {installation}\n   Permissions: {permissions} - {permission_analysis}")
                except Exception as e:
                    results.append(f"❌ {installation}\n   Error checking permissions: {e}")
            else:
                results.append(f"❌ {installation}\n   Path not accessible")
        
        return results

    def analyze_permissions(self, perm_string):
        """Analyze file permissions for security risks"""
        try:
            owner_perms = int(perm_string[0])
            group_perms = int(perm_string[1])
            other_perms = int(perm_string[2])
            
            warnings = []
            
            if other_perms >= 4:
                warnings.append("World-readable - potential risk")
            if other_perms >= 6:
                warnings.append("CRITICAL: World-writable!")
            if group_perms >= 6:
                warnings.append("Group-writable - review needed")
                
            return " | ".join(warnings) if warnings else "Secure"
        except:
            return "Unable to analyze permissions"

    def scan_common_data_locations(self):
        """Scan common locations where Discord might store data"""
        print("\n🔍 Scanning common Discord data locations...")
        
        common_data_paths = [
            "~/Library/Application Support/discord",
            "~/Library/Application Support/discordcanary", 
            "~/Library/Application Support/discordptb",
            "~/Library/Caches/com.hnc.Discord",
            "~/Library/Caches/com.hnc.DiscordCanary",
            "~/Library/Preferences/com.hnc.Discord.plist",
            "~/Library/Saved Application State/com.hnc.Discord.savedState"
        ]
        
        found_data = []
        for path_pattern in common_data_paths:
            expanded_path = os.path.expanduser(path_pattern)
            matches = glob.glob(expanded_path)
            for match in matches:
                if os.path.exists(match):
                    found_data.append(match)
                    print(f"📁 Found data location: {match}")
        
        return found_data

    def create_educational_demo(self):
        """Create educational demo files since no Discord installation was found"""
        print("\n🎓 Creating Educational Demo Files...")
        
        demo_dir = os.path.expanduser("~/discord_security_demo")
        os.makedirs(demo_dir, exist_ok=True)
        
        fake_dirs = [
            f"{demo_dir}/discord/Local Storage/leveldb",
            f"{demo_dir}/discordcanary/Cache",
            f"{demo_dir}/discordptb/Session Storage"
        ]
        
        for directory in fake_dirs:
            os.makedirs(directory, exist_ok=True)
        
        fake_tokens = [
            "NTk4NzIyNTU0NDU0NzU4MjE2.GYbA8fC.4bExample4bA8fC4bA8fC_4bA8fC4bA8fC",
            "mfa.4bA8fC4bExample4bA8fC4bA8fC_4bA8fC4bA8fC4bA8fC4bA8fC4bA8fC_4bA8fC",
            "OTI0NDU5NTgzMTY0Mjg2MDY.GbExample.4bA8fC4bA8fC_4bA8fC4bA8fC4bA8fC"
        ]
        
        for i, token in enumerate(fake_tokens):
            file_path = f"{demo_dir}/discord/Local Storage/leveldb/fake_token_{i+1}.ldb"
            with open(file_path, 'w') as f:
                f.write(f"FAKE EDUCATIONAL TOKEN - DO NOT USE\n{token}")
        
        print(f"✅ Created educational demo files in: {demo_dir}")
        return demo_dir

    def scan_for_tokens(self, directory_path=None):
        """Scan directories for potential tokens"""
        print("\n🔍 Scanning for Discord Token Patterns...")
        
        if directory_path is None:
            search_dirs = self.scan_common_data_locations()
            if not search_dirs:
                print("💡 No Discord data found. Using educational demo files...")
                demo_dir = self.create_educational_demo()
                search_dirs = [demo_dir]
        else:
            search_dirs = [directory_path]
        
        findings = []
        
        for base_dir in search_dirs:
            if not os.path.exists(base_dir):
                continue
                
            print(f"📂 Scanning: {base_dir}")
            
            file_patterns = [
                f"{base_dir}/**/*.ldb",
                f"{base_dir}/**/*.log",
                f"{base_dir}/**/*.json",
                f"{base_dir}/**/*.txt",
                f"{base_dir}/**/leveldb/*"
            ]
            
            for pattern in file_patterns:
                for file_path in glob.glob(pattern, recursive=True):
                    if os.path.isfile(file_path):
                        file_findings = self.scan_file(file_path)
                        if file_findings:
                            findings.extend(file_findings)
        
        return findings

    def scan_file(self, file_path):
        """Scan a single file for token patterns"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            for token_type, pattern in self.token_patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    findings.append({
                        'file': file_path,
                        'token_type': token_type,
                        'token_preview': f"{match[:10]}...{match[-5:]}",
                        'full_token': match,
                        'risk_level': self.assess_risk_level(token_type),
                        'note': 'EDUCATIONAL - Fake token for demonstration'
                    })
                        
        except Exception:
            pass
            
        return findings

    def assess_risk_level(self, token_type):
        """Assess risk level based on token type"""
        risk_levels = {
            'user_token': 'HIGH',
            'mfa_token': 'CRITICAL', 
            'bot_token': 'HIGH'
        }
        return risk_levels.get(token_type, 'MEDIUM')

    def analyze_token_structure(self, example_token):
        """Demonstrate how tokens are structured"""
        print("\n" + "="*50)
        print("🔐 Discord Token Structure Analysis")
        print("="*50)
        
        if example_token.startswith('mfa.'):
            print("📍 Type: MFA/2FA User Token")
            print(f"📏 Length: {len(example_token)} characters")
            print("🛡️ This token is used when the account has 2FA enabled")
            print(f"🔍 Full Token: {example_token}")
        elif len(example_token) == 59:
            parts = example_token.split('.')
            if len(parts) == 3:
                print("📍 Type: Standard User Token")
                print(f"🔢 Part 1 (User ID encoded): {parts[0]} ({len(parts[0])} chars)")
                print(f"⏰ Part 2 (Timestamp): {parts[1]} ({len(parts[1])} chars)")
                print(f"🔐 Part 3 (HMAC): {parts[2]} ({len(parts[2])} chars)")
        else:
            print("❓ Type: Unknown/Invalid Format")

    def generate_security_report(self):
        """Generate a comprehensive security report"""
        print("\n" + "🚀" + "="*48 + "🚀")
        print("           DISCORD SECURITY SCANNER REPORT")
        print("🚀" + "="*48 + "🚀")
        
        print("\n1. 📁 DIRECTORY PERMISSIONS ANALYSIS")
        print("-" * 40)
        permission_results = self.check_discord_path_permissions()
        for result in permission_results:
            print(result)
        
        print("\n2. 🔍 TOKEN SCAN RESULTS")
        print("-" * 40)
        token_findings = self.scan_for_tokens()
        if token_findings:
            print(f"⚠️  Found {len(token_findings)} potential token(s):")
            for finding in token_findings:
                print(f"   📄 File: {os.path.basename(finding['file'])}")
                print(f"   🎯 Type: {finding['token_type']}")
                print(f"   🚨 Risk: {finding['risk_level']}")
                print(f"   💬 Note: {finding['note']}")
                print(f"   👁️  Preview: {finding['token_preview']}")
                print()
        else:
            print("✅ No potential tokens found in scanned directories")
        
        print("\n3. 📚 TOKEN SECURITY EDUCATION")
        print("-" * 40)
        self.analyze_token_structure("mfa.fake_example_token_12345_abcdef_this_is_not_real_67890")

        
# Example usage
if __name__ == "__main__":
    print("Starting Enhanced macOS Discord Security Scanner...")
    
    scanner = DiscordSecurityScanner()
    scanner.generate_security_report()
    
    print("\n" + "🎯" + "="*48 + "🎯")
    print("           SCAN COMPLETE - STAY SECURE!")
    print("🎯" + "="*48 + "🎯")
