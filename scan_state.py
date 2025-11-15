"""
Scan State Management for Resume Functionality
Handles saving and loading scan progress
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List

class ScanState:
    """Manages scan state for resume functionality"""
    
    def __init__(self, state_file: str = ".scan_state.json"):
        self.state_file = state_file
        self.state = self._load_state()
    
    def _load_state(self) -> Dict[str, Any]:
        """Load state from file if it exists"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading state file: {str(e)}")
                return self._create_new_state()
        return self._create_new_state()
    
    def _create_new_state(self) -> Dict[str, Any]:
        """Create a new state dictionary"""
        return {
            'url': None,
            'session_id': None,
            'start_time': None,
            'last_update': None,
            'completed_checks': [],
            'current_check': None,
            'current_payload_index': 0,
            'results': {
                'passed': [],
                'failed': [],
                'warnings': [],
                'info': []
            },
            'status': 'new'
        }
    
    def save_state(self, state_data: Dict[str, Any]):
        """Save state to file"""
        try:
            state_data['last_update'] = datetime.now().isoformat()
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(state_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving state file: {str(e)}")
    
    def initialize_scan(self, url: str, session_id: str):
        """Initialize a new scan"""
        self.state = self._create_new_state()
        self.state['url'] = url
        self.state['session_id'] = session_id
        self.state['start_time'] = datetime.now().isoformat()
        self.state['status'] = 'in_progress'
        self.save_state(self.state)
    
    def mark_check_completed(self, check_name: str):
        """Mark a check as completed"""
        if check_name not in self.state['completed_checks']:
            self.state['completed_checks'].append(check_name)
        self.state['current_check'] = None
        self.state['current_payload_index'] = 0
        self.save_state(self.state)
    
    def set_current_check(self, check_name: str, payload_index: int = 0):
        """Set the current check being performed"""
        self.state['current_check'] = check_name
        self.state['current_payload_index'] = payload_index
        self.save_state(self.state)
    
    def add_result(self, result_type: str, result_text: str):
        """Add a result to the state"""
        if result_type in self.state['results']:
            self.state['results'][result_type].append(result_text)
            self.save_state(self.state)
    
    def mark_completed(self):
        """Mark scan as completed"""
        self.state['status'] = 'completed'
        self.save_state(self.state)
    
    def is_check_completed(self, check_name: str) -> bool:
        """Check if a specific check is completed"""
        return check_name in self.state['completed_checks']
    
    def get_completed_checks(self) -> List[str]:
        """Get list of completed checks"""
        return self.state['completed_checks']
    
    def get_current_payload_index(self) -> int:
        """Get current payload index for resume"""
        return self.state['current_payload_index']
    
    def clear_state(self):
        """Clear the state file"""
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
                self.state = self._create_new_state()
            except Exception as e:
                print(f"Error clearing state file: {str(e)}")
    
    def get_state_summary(self) -> str:
        """Get a summary of the current state"""
        summary = f"""
Scan State Summary:
  URL: {self.state['url']}
  Status: {self.state['status']}
  Start Time: {self.state['start_time']}
  Last Update: {self.state['last_update']}
  Completed Checks: {len(self.state['completed_checks'])}
  Results:
    - Passed: {len(self.state['results']['passed'])}
    - Failed: {len(self.state['results']['failed'])}
    - Warnings: {len(self.state['results']['warnings'])}
    - Info: {len(self.state['results']['info'])}
"""
        return summary
