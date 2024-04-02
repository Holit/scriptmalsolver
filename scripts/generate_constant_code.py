from bs4 import BeautifulSoup
import csv

# 读取HTML文件
with open('far_code.html', 'r',encoding='utf-8') as file:
    html_data = file.read()

# 解析HTML
soup = BeautifulSoup(html_data, 'html.parser')

# 提取表头
headers = [th.get_text().strip() for th in soup.find('thead').find_all('th')]
headers.insert(1,'value')
# 提取表格数据
data = []
for row in soup.find('tbody').find_all('tr'):
    row_data = [td.get_text().strip() for td in row.find_all('td')]
    value, code = row_data[0].split('\n')
    desc = row_data[1].replace('\n   ','')

    data.append([code, value, desc])

max_code_length = max(len(code) for code, _, _ in data)
max_value_length = max(len(str(value)) for _, value, _ in data)
max_desc_length = max(len(desc) for _, _, desc in data)
# 打开文件进行写入
with open('code.txt', 'w',encoding='utf-8') as file:
    # 用空格补齐缩进，并写入格式化后的内容
    for code, value, desc in data:
        desc = desc.replace('\n','')
        file.write(f'{code.ljust(max_code_length)} = {str(value).ljust(max_value_length)} # {desc}\n')
print('生成完成')
# 写入CSV文件
# with open('output.csv', 'w', newline='',encoding='utf-8') as csvfile:
#     writer = csv.writer(csvfile)
#     writer.writerow(headers)
#     writer.writerows(data)

# print("CSV文件已生成。")
