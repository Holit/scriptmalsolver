import csv
import datetime

class QlReports:
    def __init__(self) -> None:
        self.api_calls = []
        self.logs = []
        self.errors = []

        # 可能会在这里加入yara判别等一系列功能
        pass
    
    def insert_api_call(self, api_name, api_args):
        self.api_calls.append(
            {
                'time' : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'api_name' : api_name,
                'api_args' : api_args
            }
            )
    def insert_log(self, log_str):
        self.logs.append(
            {
                'time' : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'log_str' : log_str
            }
        )
    def insert_error(self, error_str):
        self.errors.append(
            {
                'time' : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'error_str' : error_str
            }
        )

    def get_api_calls(self):
        return self.api_calls
    def get_logs(self):
        return self.logs
    def get_errors(self):
        return self.errors
    

    def write_to_csv(input_str, filename="text.csv"):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(filename, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([current_time, input_str])

    