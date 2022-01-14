# jorgeortiz
# importing of requisite libraries
from scapy.utils import RawPcapReader	# For reading the pcap in Raw PCAP format
from scapy.layers.12 import Ether	# For reading the Ether Frame from the packets
from scapy.layers.dns import DNS, DNSQR	# For reading the DNS and DNS query
from scapy.layers.inet import IP, UDP	# For reading the IP header
import tldextract			#Extracting TLD Domain names
import matplotlib.pyplot as plt		#For plotting the results


def calculate_score (ip_set_1, ip_set_2):
	return len (ip_set_1.intersection (ip_set_2))	/
len (ip_set_1.union(ip_set_2))


# Method to extract unique Domain Name and create Dict with the src IP as values.
def dns_dict (file_name) :
dns_pkt_count = 0
dns_data = []
i = 0

	for (pkt_data, pkt_metadata) in RawPcdaReader(file_name) :	# read the PCAP file in Raw Format
		frm = Ether(pkt_data)	# Read Frame(frm) from packet
		i + =1			# Counter for Each Packet in the PCAP file.
	

		try:
		   if i % 1000 == 0:
			print('On packet number ', i)
		   if DNS in frm and frm[IP] .proto == 17:	# Filter UDP packets IP Protocol Type 17
			if frm [UDP] .deport == 53:		# Filer all packets with Destination Port as 53
				dns_pkt_count += 1		# Counter for DNS Packets
				new_ip = ''			# Blank string for concatenation of IP Addr without '.'
				ip = frm[IP] .src.split('.')	# Spliting octets of IP Addr as items in a lists
				for j in range(4) :
					single = '0'
					double = '00'
					if int (ip [j])	< 10:
						double += ip[j]
						ip[j] = double	# Add '00' to octet with only one digit
					elif int (ip[j]) < 100:
						single += ip [j]
						ip[j] = single 	# Add '0' to octet with two digits
					for k in range (4):
						new_ip += ip [k]  # Concatenate IP Addr as a str with 12 numerals
								  # Concatenate Time in Sec and Milisec as a str with '.' in between
						time = str(pkt_metadata.sec)	# Add the URL, IP Str and time Str as a list in the dns_data
						dns_data.append (([frm[DNSQR].qname, new_ip,int (time)]))
			except:
			     print('check pkt no ', i)		# Throw exception, if the packet is not meeting the conditions.
			f = open('top10k.txt')			# top10k.txt containing the top 10,000 Domain names
			top10k.txt = f.read()			# from www.alexa.com
			top_names = top10k.split('\n')		# load the domain names intro a list

			print('DONE WITH PARSING ALL PACKETS')
			for  i in range(len(dns_data)):
				name = dns_data[i] [0]		# reason for decode: https://stackoverflow.com/questions/606191/convert-byte-to-a-string
				tld_extracted = tldxtract.extract (name.decode("utf-8"))
				dns_data [i] [0] = tld_extracted.domain + '.' + tld_extracted.suffix
			dns_final = []			# List to extract DNS data not in the list of top 10,000 websites.

			for  i in range(len(dns_data)):	
				if dns_data[i] [0] not in top_names:
					dns_final.append(dns_data[i])
			print(dns_final)		# dns_final = []	# List to extract DNS data not in the list of top 10,000 websites.

			start_time = dns_final [0] [2]

			time_now = start-time
			dns_date_hrly = []
			i = 0
			
			while (i < len(dns_final)) :
			temp = []
			time_now + dns_final[i][2] - start_time
			hr = time_now / 5400
			temp = [int(hr), dns_final [i][0], dns_final [i] [1]]
			dns_data_hrly.append(temp)
			i +=1
		# Next four lines removes duplicates.It inserts elements from dns_data_hrly into
	# a new list if they didn't exist in the newlist already. So by the end of it
	# newlist will only have unique elements.
	
	newlist = []
	for data in dns_data_hrly:
	if data not in newlist:
		newlist.append(data)

	# newlist = [['0', 'a.com','100'], ['0', 'a.com', '110'],['1', 'a.com', '110'],['1', 'b.com', '110']]
	# Create a dict of dicts with the structure -> dict(dns: dict(hour: [host])
		master_dict = dict ()
		for hour, dns, host in newlist:
			if dns not in master_dict:
				master_dict[dns] = dict()
			if hour not in master_dict[dns]:
				master_dict[dns] [hour] = {host}
			else:
				master_dict[dns] [hour] .add(host)
		print(master_dict)
		print('MASTER DICTIONARY PRINTED')
		# google.com -> (0: {a}, 1:{b}, 2:{c})
		pairwise_score = dict()
		score_threshold = 0.2
		within_domain_ip_length_threshold = 3
		for domain, sub_dict in master_dict.items():
		for hour_1, ip_set_1 in sub_dict.items():
			for hour_2, ip_set_2 in sub_dict.items():
			# remove cases where we swap hour 1 and hour 2
			# if you remove the greater than, then entries will be 2 -- 3 and 3 -- 2
			if (hour_1 >= hour_2):
				continue
			if (min(len(ip_set_1), len(ip_set_2)) < within_domain_ip_length_threshold):
				continue

			score = calculate_score(ip_set_1, ip_set_2)
			if (score < score_threshold):
				continue

			key_for_dict = str(hour_1) + " -- " + str(hour_2)
			if domain not in pairwise_score:
				pairwise_score[domain] = dict()
			pairwise_score[domain] [key_for_dict] = score

		print(type(pairwise_score), pairwise_score)
		print ('PAIRWISE SCORE PRINTED')

		pair_plot = []
		
		for i,j in pairwise_score.items():
			for k,z in j.items():
				if z != 1:
					a = [i,z]
					pair_plot.append(a)

		# for key1, val1 in val.items():
		# pair_plot.append([key,vall]
		# code for domain migration, uncomment below, takes lot of time

		across_domain_check = []
		len_threshold_percentage = 10
		min_length_threshold = 5
		
		for domain, sub_dict in master_dict.items():
			for hour, ip_set in sub_dict.items():
				for other_domain, other_sub_dict in master_dict.items():
					for other_hour, other_ip_set in other_sub_dict.items():
						if (domain == other_domain):
							continue
						if (hour == other_hour):
							continue
						if min(len(len(ip_set), len(other_ip_set) < min_length_threshold):
							continue
						if (100 * abs(len(ip_set) - len(other_ip_set)) / min(len(ip_set),
						len(other_ip_set)) > len_threshold_percentage):
							continue
						score = calculate_score(ip_set, other_ip_set)
						if (score < score_thewshold):
							continue
						across_domain_check.append([domain, other_domain, hour, other_hour, ip_set, other_ip_set, score])
				print(across_domain_check)
				return pair_plot
			file_name1 = 'ctu 9 dns only.pcap'
			table1 = dns_dict(file_name1)
			a, b = zip(*table1)


		plt.rc('figure' figsize=(16, 12))
		plt.title ('DNS query vs similarity')
		plt.xlablel ('DNS name')
		plt.ylabel ('similarity')
		plt.bar (a, b)			# plot a bar graph
		plt.xticks(rotation=90)		# rotate the X-Axis (domain names)
		plt.show()			# display  the plot
