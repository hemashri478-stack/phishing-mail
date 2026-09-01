#!/usr/bin/env python3
"""
Copy dashboard data to dashboard directory
"""

import shutil
import os
import json

def copy_dashboard_data():
    """Copy dashboard_data.json to dashboard directory"""
    source_file = 'dashboard_data.json'
    dashboard_dir = 'dashboard'
    target_file = os.path.join(dashboard_dir, 'dashboard_data.json')
    
    try:
        # Check if source file exists
        if not os.path.exists(source_file):
            print(f"⚠️  {source_file} not found. Creating empty file...")
            # Create empty dashboard data
            empty_data = {
                "websiteHistory": [],
                "message": "No analysis data available yet"
            }
            with open(source_file, 'w') as f:
                json.dump(empty_data, f, indent=2)
        
        # Create dashboard directory if it doesn't exist
        if not os.path.exists(dashboard_dir):
            os.makedirs(dashboard_dir)
            print(f"📁 Created dashboard directory: {dashboard_dir}")
        
        # Copy the file
        shutil.copy2(source_file, target_file)
        print(f"✅ Copied {source_file} to {target_file}")
        
        # Verify the copy
        if os.path.exists(target_file):
            print(f"✅ Verification: {target_file} exists")
            
            # Read and display some stats
            try:
                with open(target_file, 'r') as f:
                    data = json.load(f)
                    history = data.get('websiteHistory', [])
                    print(f"📊 Dashboard data contains {len(history)} website analyses")
                    
                    if history:
                        print("📋 Recent analyses:")
                        for i, site in enumerate(history[:3]):
                            url = site.get('url', 'Unknown')
                            risk = site.get('riskScore', 0)
                            recommendation = site.get('recommendation', 'Unknown')
                            print(f"   {i+1}. {url[:50]}... (Risk: {risk}/10, {recommendation})")
                    else:
                        print("📋 No analyses found in data")
                        
            except Exception as e:
                print(f"⚠️  Error reading dashboard data: {e}")
        else:
            print(f"❌ Error: {target_file} was not created")
            
    except Exception as e:
        print(f"❌ Error copying dashboard data: {e}")

if __name__ == '__main__':
    print("🔒 ShadowLens - Copy Dashboard Data")
    print("=" * 40)
    copy_dashboard_data()
    print("=" * 40)
    print("✅ Dashboard data copy complete!")
    print("🌐 To view dashboard: cd dashboard && python3 server.py")
    print("📊 Then open: http://localhost:8080") 