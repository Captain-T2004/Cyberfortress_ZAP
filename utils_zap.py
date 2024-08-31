import requests
import time
import json
from config import Config
from zapv2 import ZAPv2
from utils_common import generate_random, save_scan_results_to_db

def active_scan(target, endpoints_json, zap_api_url='http://localhost:8080'):
    try:
        zap = ZAPv2(apikey=Config.ZAP_API_KEY, proxies={'http': zap_api_url, 'https': zap_api_url})
        endpoints = json.loads(endpoints_json)
        all_alerts = {}
        
        # Create a new context
        context_name = generate_random(10)
        context_id = zap.context.new_context(context_name)
        print(f"Created new context with ID: {context_id}")
        
        # Add target to context
        zap.context.include_in_context(context_name, f"{target}.*")
        print(f"Added {target} to context")
        
        # Set the context in scope
        zap.context.set_context_in_scope(context_name, True)
        print(f"Set context {context_name} in scope")
        
        # Combine discovered URLs with provided endpoints
        all_endpoints = list([f"{target}{endpoint}" for endpoint in endpoints])
        all_endpoints.sort()
        
        for full_url in all_endpoints:
            print(f"Processing: {full_url}")
            alertOrNot = 0
            try:
                # Force browse the URL to ensure it's in the Sites tree
                response = zap.core.access_url(full_url)
                print(f"Accessed URL: {full_url}")
                
                # Start the active scan with a higher strength and thread count
                scan_id = zap.ascan.scan(full_url, contextid=context_id, scanpolicyname="Default Policy")
                print(f"Started scan with ID: {scan_id}")
                
                # Wait for the scan to complete
                while int(zap.ascan.status(scan_id)) < 100:
                    print(f"Scan progress: {zap.ascan.status(scan_id)}%")
                    time.sleep(5)
                
                print("Scan completed. Fetching alerts...")
                alerts = zap.core.alerts(baseurl=full_url)
                endpoint_alerts = []
                
                for alert in alerts:
                    temp = {
                        "alert": alert["alert"],
                        "risk": alert["risk"],
                        "confidence": alert["confidence"]
                    }
                    endpoint_alerts.append(temp)
                    if alert["risk"] == "High" and alert["confidence"] == "High":
                        alertOrNot = 1
                
                unique_alerts = list({v["alert"]: v for v in endpoint_alerts}.values())
                unique_alerts.append({'alertOrNot': str(alertOrNot)})
                all_alerts[full_url.replace(target, '')] = unique_alerts
                print(f"Processed {len(unique_alerts)-1} unique alerts for {full_url}")
            
            except Exception as e:
                print(f"Error processing {full_url}: {str(e)}")
        
        save_scan_results_to_db(all_alerts)
        print(all_alerts)
        zap.context.remove_context(context_name)
        return alertOrNot, all_alerts
    
    except Exception as e:
        print(f"Error in active_scan: {str(e)}")
        return None

def limit_ascan(apikey):
    headers = {"Accept": "application/json"}
    try:
        res = requests.get(
            "http://localhost:8080/JSON/ascan/action/disableAllScanners/",
            headers=headers,
            params={"apikey":apikey}
        )
        """
            Path Traversal (Alert ID: 6)
	        Command Injection (Alert ID: 90020)
            .env Information Leak (Alert ID: 40034)
	        Cloud Metadata Attack (Alert ID: 90034)
	        SQL Injection (multiple alert IDs: 40018, 40019, 40020, etc.)
            Buffer Overflow (Alert ID: 30001)
            Remote Code Execution - CVE-2012-1823 (Alert ID: 20018)
            Parameter Tampering (Alert ID: 40008)
            Log4Shell (Alert ID: 40043)
            Spring4Shell (Alert ID: 40045)

	    """
        res = requests.get(
            "http://localhost:8080/JSON/ascan/action/enableScanners/",
            params={"ids": "6,90020,40034,90034,40018, 40019, 40020, 30001,20018,40008,40043,40045", "apikey":apikey},
            headers=headers,
        )
        return res.json()
    except:
        return None

def report(target,apikey):
    headers = {"Accept": "application/html"}
    name = generate_random(10)
    try:
        requests.get(
            "http://localhost:8080/JSON/reports/action/generate/",
            params={
                "title": "Vulture Scan Report",
                "template": "traditional-pdf",
                "sites": target,
                "reportFileName": name,
                "reportDir": "/home/ubuntu/Vulture_ZAP/static",
                "apikey":apikey,
            },
            headers=headers,
        )
        return name
    except:
        return None
