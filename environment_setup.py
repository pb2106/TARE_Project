#!/usr/bin/env python3
"""
Environment Setup Module - Simplified and Tested Version
Creates the directory structure for forensic analysis
"""

import os
import json
from pathlib import Path
from datetime import datetime


class EnvironmentSetup:
    """
    Sets up the forensic analysis environment with all necessary directories
    and configuration files.
    """
    
    def __init__(self, base_path="forensic_project"):
        """
        Initialize the environment setup
        
        Args:
            base_path: Base directory name (default: "forensic_project")
        """
        self.base_path = Path(base_path).absolute()
        
        # Define directory structure
        self.directories = {
            'test_environment': {
                'user_files': 'test_environment/user_files',
                'browser_data': 'test_environment/browser_data',
                'system_logs': 'test_environment/system_logs',
                'temp_files': 'test_environment/temp_files',
                'deleted_files': 'test_environment/deleted_files'
            },
            'evidence': 'evidence',
            'reports': 'reports',
            'config': 'config'
        }
        
        # Configuration data
        self.config = {
            'project_name': 'Digital Forensics Analysis',
            'version': '1.0',
            'created': datetime.now().isoformat(),
            'settings': {
                'log_level': 'INFO',
                'max_file_size_mb': 100,
                'temp_retention_days': 7
            }
        }
    
    def setup_environment(self):
        """
        Create all required directories and configuration files
        
        Returns:
            dict: Status information about the setup
        """
        print("=" * 70)
        print("FORENSIC ENVIRONMENT SETUP")
        print("=" * 70)
        print(f"\n[*] Base directory: {self.base_path}")
        
        # Step 1: Create base directory
        print("\n[STEP 1/4] Creating base directory...")
        try:
            self.base_path.mkdir(exist_ok=True)
            print(f"✓ Created: {self.base_path}")
        except Exception as e:
            print(f"✗ Error creating base directory: {e}")
            return {'status': 'failed', 'error': str(e)}
        
        # Step 2: Create all subdirectories
        print("\n[STEP 2/4] Creating subdirectories...")
        created_dirs = []
        
        for main_dir, sub_items in self.directories.items():
            if isinstance(sub_items, dict):
                # This is a parent with children (like test_environment)
                for sub_dir, path in sub_items.items():
                    full_path = self.base_path / path
                    try:
                        full_path.mkdir(parents=True, exist_ok=True)
                        created_dirs.append(full_path)
                        print(f"  ✓ {path}")
                    except Exception as e:
                        print(f"  ✗ Failed to create {path}: {e}")
            else:
                # This is a standalone directory
                full_path = self.base_path / sub_items
                try:
                    full_path.mkdir(parents=True, exist_ok=True)
                    created_dirs.append(full_path)
                    print(f"  ✓ {sub_items}")
                except Exception as e:
                    print(f"  ✗ Failed to create {sub_items}: {e}")
        
        print(f"\n✓ Created {len(created_dirs)} directories")
        
        # Step 3: Create configuration file
        print("\n[STEP 3/4] Creating configuration file...")
        config_path = self.base_path / 'config' / 'config.json'
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"✓ Created: {config_path}")
        except Exception as e:
            print(f"✗ Failed to create config file: {e}")
        
        # Step 4: Create README
        print("\n[STEP 4/4] Creating README...")
        readme_path = self.base_path / 'README.md'
        try:
            readme_content = self._generate_readme()
            with open(readme_path, 'w') as f:
                f.write(readme_content)
            print(f"✓ Created: {readme_path}")
        except Exception as e:
            print(f"✗ Failed to create README: {e}")
        
        print("\n" + "=" * 70)
        print("✓ ENVIRONMENT SETUP COMPLETE!")
        print("=" * 70)
        
        return {
            'status': 'success',
            'base_path': str(self.base_path),
            'directories_created': len(created_dirs),
            'config_path': str(config_path),
            'readme_path': str(readme_path)
        }
    
    def _generate_readme(self):
        """Generate README content"""
        return f"""# Forensic Analysis Environment

## Directory Structure

```
forensic_project/
├── test_environment/          # Simulated test environment
│   ├── user_files/           # User documents and files
│   ├── browser_data/         # Browser history, cache, cookies
│   ├── system_logs/          # System and application logs
│   ├── temp_files/           # Temporary files
│   └── deleted_files/        # Deleted files area
├── evidence/                  # Collected forensic evidence
├── reports/                   # Generated forensic reports
└── config/                    # Configuration files
```

## Purpose

This environment is used for forensic analysis training and testing.

## Usage

1. Run user activity simulation modules
2. Simulate file deletions
3. Perform forensic analysis
4. Generate reports

## Created

{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Version

{self.config['version']}
"""
    
    def verify_environment(self):
        """
        Verify that all directories exist
        
        Returns:
            dict: Verification results
        """
        print("\n[*] Verifying environment...")
        
        all_exist = True
        missing = []
        existing = []
        
        # Check all directories
        for main_dir, sub_items in self.directories.items():
            if isinstance(sub_items, dict):
                for sub_dir, path in sub_items.items():
                    full_path = self.base_path / path
                    if full_path.exists():
                        existing.append(path)
                    else:
                        all_exist = False
                        missing.append(path)
            else:
                full_path = self.base_path / sub_items
                if full_path.exists():
                    existing.append(sub_items)
                else:
                    all_exist = False
                    missing.append(sub_items)
        
        if all_exist:
            print(f"✓ All {len(existing)} directories verified")
        else:
            print(f"✗ Missing {len(missing)} directories")
            for m in missing:
                print(f"  - {m}")
        
        return {
            'valid': all_exist,
            'existing_directories': existing,
            'missing_directories': missing
        }
    
    def get_path(self, directory_type):
        """
        Get full path for a specific directory type
        
        Args:
            directory_type: Name of directory (e.g., 'evidence', 'reports')
        
        Returns:
            Path object or dict of Path objects
        """
        if directory_type in self.directories:
            if isinstance(self.directories[directory_type], dict):
                return {k: self.base_path / v for k, v in self.directories[directory_type].items()}
            else:
                return self.base_path / self.directories[directory_type]
        return None
    
    def list_structure(self):
        """
        Display the directory structure
        """
        print("\n" + "=" * 70)
        print("DIRECTORY STRUCTURE")
        print("=" * 70)
        print(f"\n{self.base_path}/")
        
        for main_dir, sub_items in self.directories.items():
            if isinstance(sub_items, dict):
                print(f"├── {main_dir}/")
                items = list(sub_items.items())
                for i, (sub_dir, path) in enumerate(items):
                    is_last = (i == len(items) - 1)
                    prefix = "    └──" if is_last else "    ├──"
                    print(f"{prefix} {sub_dir}/")
            else:
                print(f"├── {sub_items}/")
        
        print("=" * 70)


def main():
    """
    Main function for testing the environment setup
    """
    print("\nForensic Environment Setup Module")
    print("Version 1.0\n")
    
    # Create environment setup instance
    env = EnvironmentSetup("forensic_project")
    
    # Setup the environment
    result = env.setup_environment()
    
    # Verify the environment
    verification = env.verify_environment()
    
    # Display structure
    env.list_structure()
    
    # Print summary
    print("\n" + "=" * 70)
    print("SETUP SUMMARY")
    print("=" * 70)
    print(f"Status: {result['status']}")
    print(f"Base Path: {result['base_path']}")
    print(f"Directories Created: {result['directories_created']}")
    print(f"Verification: {'PASSED' if verification['valid'] else 'FAILED'}")
    print("=" * 70)
    
    return result


if __name__ == "__main__":
    main()
