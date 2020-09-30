#!/usr/bin/env python

#OBJECT_ADDED_SUCCESSFULLY = 0
#ENTRY_IS_ALREADY_ADDED = 1
#ERROR_WHILE_ADDING_ENTRY = 2
#SET_CREATED_SUCCESSFULLY = 3
#ERROR_WHILE_CREATING_SET = 4
#POLICY_WAS_ADDED_SUCCESSFULLY = 5
#ERROR_WHILE_ADDING_POLICY = 6
#OBJECT_DELETED_SUCCESSFULLY = 7
#ERROR_WHILE_DELETING_OBJECT = 8
#IPSET_DESTROYED_SUCCESSFULLY = 9
#ERROR_WHILE_DESTROYING_IPSET =10



import subprocess as sb
import iptc
import logging
import jdatetime
import shlex


tcp_port_list={'FTP' : '20/21', 'SSH' : '22', 'Telnet' : '23', 'SMTP' : '25',
			   'DNS' : '53', 'HTTP' : '80', 'POP' : '110', 'NetBIOS' : '137/138/139',
			   'IMAP' : '143', 'SNMP' : '161/162', 'BGP' : '179', 'LDAP' : '389',
			   'HTTPS' : '443', 'MICROSOFT-DS' : '445', 'SMTPS' : '25/465', 'LDAPS' : '636',
			   'FTPS' : '989/990', 'IMAPS' : '993', 'MS-SQL-S' : '1433',
			   'MS-SQL-M' : '1434', 'RDP' : '3389'}

udp_port_list={'DNS' : '53', 'DHCP' : '67/68', 'TFTP' : '69', 'NTP' : '123', 'NetBIOS' : '137/138/139', 'SNMP' : '161/162',
			   'LDAP' : '389', 'LDAPS' : '636', 'MS-SQL-S' : '1433', 'MS-SQL-M' : '1434'}

#this is my damn magic -________-
def getAllSets():
	out = sb.Popen(['sudo', 'ipset_list'], shell = False, stdout = sb.PIPE)
	res, err = out.communicate()
	if res:
		sets = res.split("\n")
		for i in range(0, len(sets)):
			sets[i] = sets[i][6:]
	if res:
		sets.remove('')
		return sets
	else:
		return []

def ipset_logging_configs(logger):
	fhl = logging.FileHandler('ipset.log')
	formatter = logging.Formatter('%(asctime)s - %(levelname)s : %(message)s')
	logger.setLevel(logging.DEBUG)

	ch = logging.StreamHandler()
	logger.addHandler(ch)
	ch.setFormatter(formatter)
	ch.setLevel(logging.DEBUG)

	logger.addHandler(fhl)
	fhl.setFormatter(formatter)
	fhl.setLevel(logging.DEBUG)

def JalaliToGregorian(date):
	temp = date.split("/")
	(y, m, d) = jdatetime.JalaliToGregorian(int(temp[0]), int(temp[1]), int(temp[2])).getGregorianList()
	return (str(y) + '-' + str(m) + '-' + str(d))

def deleteAddressSet(setName):
	out = sb.Popen(['sudo', 'ipset_list', '-Ht', 'list:set'], shell = False, stdout = sb.PIPE)
	res, err = out.communicate()
	if res:
		temp = res.split("\n")
		temp.remove('')
		temp.remove('')
		for value in temp:
			value = value[6:]
			print setName,value
			print '------------------------deleteaddress--------------------------'
			z_out = sb.Popen(['sudo', 'ipset_list', '-i', '-Fr', setName, value], shell = False, stdout = sb.PIPE)
			result, error = z_out.communicate()
			if result:
				delete_entry(value, setName)
		destroy_ipset(setName)

def create_bitmap_port_ipset(set_name):
	out = sb.Popen(['sudo', 'ipset', '-N', set_name, 'bitmap:port','range','0-65535', 'comment'], shell = False,
			  stderr = sb.PIPE)
	res, err = out.communicate()
	if err:
		logger.debug('%s' %err)
	else:
		logger.debug('IPset named %s of type bitmap:port was created successfully' % (set_name))
		sb.call('sudo ipset save > /usr/local/etc/ipsetSave.conf', shell = True)
		# sb.Popen(['/etc/ipset_save.sh'], shell = False)


# def create_hash_ip_set(set_name, netmask='32', comment=False):
#	 if comment:
#		 sb.call(['sudo', 'ipset', '-N', set_name, 'hash:ip', 'netmask', netmask])
#	 else:
#		 sb.call(['sudo', 'ipset', '-N', set_name, 'hash:ip', 'netmask', netmask, 'comment'])
#	 logger.debug('ipset named %s of type hash:ip was created successfully' % set_name)



#it is used for creating ipsets which don't require some addtional fields like range
def create_unranged_ipset(set_name, set_type):
	out = sb.Popen(['sudo', 'ipset', '-N', set_name, set_type, 'comment'], shell = False, stderr = sb.PIPE)
	res,err = out.communicate()
	if err:
		logger.debug('%s' %err)
	else:
		logger.debug('IPset named %s of type %s was created successfully' % (set_name, set_type))
		sb.call('sudo ipset save > /etc/Firewall/ipsetSave.conf', shell = True)
		#sb.Popen(['/etc/ipset_save.sh'], shell = False)


#it deletes a single entry from a special ipset
def delete_entry(set_name, entry_value):
	out = sb.Popen(['sudo', 'ipset', 'del', set_name, entry_value], shell = False, stderr = sb.PIPE)
	res, err = out.communicate()
	if not err:
		logger.debug('Entry %s was deleted from set %s successfully' % (entry_value, set_name))
		#sb.Popen(['/etc/ipset_save.sh'], shell = False)
		sb.call('sudo ipset save > /etc/Firewall/ipsetSave.conf', shell = True)
	else:
		logger.debug('%s' %err)



#it adds a single entry to ipset
def add_single_entry(set_name, entry_value ,comment=""):
	if comment:
		comment = "(" + set_name + ") " + comment
	else:
		comment =  "(" + set_name + ")"
	out = sb.Popen(['sudo', 'ipset', '-A', set_name, entry_value, 'comment', comment ], shell = False, stderr = sb.PIPE)
	out.wait()
	err = out.communicate()
	if err[1]:
		logger.debug('%s' %err[1])
		return 1
	else:
		logger.debug('Entry %s was added successfully in set %s' %(entry_value, set_name))
		#sb.Popen(['/etc/ipset_save.sh'], shell = False)
		return 0


# def delete_unused_protocols(policy_name, protocol):
# 	#FORWARD
# 	out = sb.Popen(['sudo', 'iptables', '-L', policy_name+'_FORWARD'], shell = False, stdout = sb.PIPE)
# 	res,err = out.communicate()
# 	if not err and res:
# 		splited = res.split("\n")
# 		for i in range(2, len(splited)):
# 			if protocol in splited[i]:
# 				sb.Popen(['sudo', 'iptables', '-D', policy_name+'_FORWARD', str(int(i)-1)], shell = False)
# 	#PREROUTING
# 	out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-L', policy_name+'_DNAT'], shell = False, stdout = sb.PIPE)
# 	res,err = out.communicate()
# 	if not err and res:
# 		splited = res.split("\n")
# 		for i in range(2, len(splited)):
# 			if protocol in splited[i]:
# 				sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', policy_name+'_DNAT', str(int(i)-1)], shell = False)


#it edits a single entry
#NOTE: it deoesn't have any return value
def edit_address_ipset(old_set_name, new_set_name, new_type, old_type, new_value, old_value):
	if old_set_name == new_set_name  and new_type == old_type:
		delete_entry(old_set_name, old_value)
		add_entry(new_set_name, new_value)
		logger.debug("Entry in set %s was replaced with %s in set %s" %(old_set_name, new_value, new_set_name))	
		sb.call('sudo ipset save > /usr/local/etc/ipsetSave.conf', shell = True)
		return False
	else:
		if new_type == "iprange" or new_type == "fqdn":
			create_unranged_ipset(new_set_name, "hash:ip")
		if new_type == "subnet":
			create_unranged_ipset(new_set_name, "hash:net")
		if new_type == "mac":
			create_unranged_ipset(new_set_name, "hash:mac")
		add_entry(new_set_name, new_value)
			# if value == "ICMP":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_ICMP', 'bitmap:port', 'range', '0-0'])
			# elif value == "GRE":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_GRE', 'bitmap:port', 'range', '0-0'])
			# elif value == "EIGRP":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_EIGRP', 'bitmap:port', 'range', '0-0'])
			# elif value == "IPSEC-ESP":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_IPSEC-ESP', 'bitmap:port', 'range', '0-0'])
			# elif value == "IPSEC-AH":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_IPSEC-AH', 'bitmap:port', 'range', '0-0'])
			# elif value == "L2TP":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_L2TP', 'bitmap:port', 'range', '0-0'])
			# elif value == "OSPF":
			# 	sb.Popen(['sudo', 'ipset', 'create', new_set_name+'_OSPF', 'bitmap:port', 'range', '0-0'])
			# elif value[:3] == 'tcp':
			# 	create_bitmap_port_ipset(new_set_name+'_TCP')
			# 	value = value[4:]
			# 	add_entry(new_set_name'_TCP', value, comment)
			# elif value[:3] == 'udp':
			# 	create_bitmap_port_ipset(new_set_name+'_UDP')
			# 	value = value[4:]
			# 	add_entry(new_set_name'_UDP', value, comment)
	logger.debug("Entry with value of {%s} in set (%s) was replaced with {%s} in set (%s)" %(old_value, old_set_name, new_value, new_set_name))	
	sb.call('sudo ipset save > /usr/local/etc/ipsetSave.conf', shell = True)
	return True


def edit_port_set(old_set_name, new_set_name, new_value, old_value):
	try:
		#if old_set_name == new_set_name:
		oldSplited = old_value.split(":")
		newSplited = new_value.split(":")
		oldNew = [item for item in oldSplited if item not in newSplited]
		newOld = [item for item in newSplited if item not in oldSplited]

		for value in oldNew:
			if value == "ICMP":
				destroy_ipset(old_set_name+'_ICMP')
			elif value == "GRE":
				destroy_ipset(old_set_name+'_GRE')
			elif value == "IGMP":
				destroy_ipset(old_set_name+'_IGMP')
			# elif value == "EIGRP":
			# 	destroy_ipset(old_set_name+'_EIGRP')
			elif value == "IPSEC-ESP":
				destroy_ipset(old_set_name+'_IPSEC-ESP')
			elif value == "IPSEC-AH":
				destroy_ipset(old_set_name+'_IPSEC-AH')
			# elif value == "L2TP":
			# 	destroy_ipset(old_set_name+'_L2TP')
			# elif value == "OSPF":
			# 	destroy_ipset(old_set_name+'_OSPF')
			elif (value[:3] == 'tcp' or value in tcp_port_list) :
				tcpFlag1 = True
				out = sb.Popen(['sudo', 'ipset', 'flush', old_set_name + '_TCP'], shell = False, stdout = sb.PIPE)
				res, err = out.communicate()
				out = sb.Popen(['sudo', 'ipset', 'destroy', old_set_name + '_TCP'], shell = False, stdout = sb.PIPE)
				res, err = out.communicate()
			elif (value[:3] == 'udp' or value in udp_port_list):
				udpFlag1 = True
				out = sb.Popen(['sudo', 'ipset', 'flush', old_set_name + '_UDP'], shell = False, stdout = sb.PIPE)
				res, err = out.communicate()
				out = sb.Popen(['sudo', 'ipset', 'destroy', old_set_name + '_UDP'], shell = False, stdout = sb.PIPE)
				res, err = out.communicate()

		if old_set_name == new_set_name:
			for value in newOld:
				if value == "ICMP":
					sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_ICMP', 'bitmap:port', 'range', '0-0'], shell = False)
				elif value == "GRE":
					sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_GRE', 'bitmap:port', 'range', '0-0'], shell = False)
				elif value == "IGMP":
					sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_IGMP', 'bitmap:port', 'range', '0-0'], shell = False)
				# elif value == "EIGRP":
				# 	sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_EIGRP', 'bitmap:port', 'range', '0-0'], shell = False)
				elif value == "IPSEC-ESP":
					sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_IPSEC-ESP', 'bitmap:port', 'range', '0-0'], shell = False)
				elif value == "IPSEC-AH":
					sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_IPSEC-AH', 'bitmap:port', 'range', '0-0'], shell = False)
				# elif value == "L2TP":
				# 	sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_L2TP', 'bitmap:port', 'range', '0-0'], shell = False)
				# elif value == "OSPF":
				# 	sb.Popen(['sudo', 'ipset', '-N', new_set_name + '_OSPF', 'bitmap:port', 'range', '0-0'], shell = False)
				elif value[:3] == 'tcp': 
					create_bitmap_port_ipset(new_set_name + '_TCP')
					for port in (value.split("=")[1]).split(',') :
						add_entry(new_set_name + '_TCP',port )
				elif value[:3] == 'udp':
					create_bitmap_port_ipset(new_set_name + '_UDP')
					for port in (value.split("=")[1]).split(',') :
						add_entry(new_set_name + '_UDP',port )
				elif value in tcp_port_list:
					tcp_ports = tcp_port_list[value].split("/")
					for j in range(0,len(tcp_ports)):
						create_bitmap_port_ipset(new_set_name + '_TCP')
						add_entry(new_set_name + '_TCP', tcp_ports[j])
				elif value in udp_port_list:
					udp_ports = udp_port_list[value].split("/")
					for j in range(0,len(udp_ports)):
						create_bitmap_port_ipset(new_set_name + '_UDP')
						add_entry(new_set_name + '_UDP', udp_ports[j])
		else:
			add_portrange(new_set_name ,new_value)
	except Exception as e:
		logger.debug(e)
	else:
		logger.debug('Entry with value of {%s} in set (%s) was replaced with {%s} in set (%s)' %(old_value, old_set_name, new_value, new_set_name))



#it destroys an ipset
def destroy_ipset(set_name):
	out = sb.Popen(['sudo', 'ipset', 'destroy', set_name], shell = False, stderr = sb.PIPE)
	res, err = out.communicate()
	if err:
		logger.debug("%s" %err)
	else:
		logger.debug('IPset %s was destroyed completely' %set_name)
		sb.call('sudo ipset save > /usr/local/etc/ipsetSave.conf', shell = True)
		#sb.Popen(['/etc/ipset_save.sh'], shell = False)

	# err = out.communicate()
	# if not err[1]:
	#	 logger.debug('IPset %s was destroyed completely' %set_name)
	#	 IPSET_OBJECTS.remove(set_name)
	#	 #sb.Popen(['/etc/ipset_save.sh'], shell = False)
	#	 return 9
	# else:
	#	 logger.debug("%s" %err[1])
	#	 return 10




#it deletes a policy from iptables
#NOTE: it doesn't have any return value
def delete_policy(policy_name):
	#FORWARD
	#sb.Popen(['sudo', 'iptables', '-D', 'FORWARD', get_forward_index(policy_name)], shell = False)
	table = iptc.Table(iptc.Table.FILTER)
	index = get_forward_index(policy_name+'_FORWARD')
	if index:
		out = sb.Popen(['sudo', 'iptables', '-D', 'FORWARD', index], shell = False)
		res, err = out.communicate()
	table.refresh()
	if table.is_chain(policy_name + '_FORWARD'):
		out = sb.Popen(['sudo', 'iptables', '-F', policy_name + '_FORWARD'], shell = False)
		res, err = out.communicate()
		out = sb.Popen(['sudo', 'iptables', '-X', policy_name + '_FORWARD'], shell = False)
		res, err = out.communicate()

		# table.refresh()
		# index = get_forward_index(policy_name+'_FORWARD')
		# if index:
		# 	chain = iptc.Chain(table, 'FORWARD')
		# 	rules = chain.rules
		# 	chain.delete_rule(rules[int(index) - 1 ])
		# 	table.refresh()
		# f_Chain = iptc.Chain(table, policy_name+'_FORWARD')
		# f_Chain.flush()
		# f_Chain.delete()
		# table.commit()
		# table.refresh()
	#PREROUTING
	d_Table = iptc.Table(iptc.Table.NAT)
	index = get_publish_index(policy_name + '_DNAT')
	if index:
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', index], shell = False)
		res, err = out.communicate()
	d_Table.refresh()
	if d_Table.is_chain(policy_name + '_DNAT'):
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-F', policy_name + '_DNAT'], shell = False)
		res, err = out.communicate()
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-X', policy_name + '_DNAT'], shell = False)
		res, err = out.communicate()
		# d_Table.refresh()
		# index = get_publish_index(policy_name + '_DNAT')
		# if index:
		# 	chain = iptc.Chain(d_Table, 'PREROUTING')
		# 	rules = chain.rules
		# 	chain.delete_rule(rules[int(index) - 1])
		# d_Chain = iptc.Chain(d_Table, policy_name+'_DNAT')
		# d_Chain.flush()
		# d_Chain.delete()
		# d_Table.commit()
		# d_Table.refresh()
	#PREROUTING
	index = get_nat_index(policy_name + '_NAT')
	#d_Table.refresh()
	if index:
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', index], shell = False)
		res, err = out.communicate()
	d_Table.refresh()
	if d_Table.is_chain(policy_name + '_NAT'):
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-F', policy_name + '_NAT'], shell = False)
		res, err = out.communicate()
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-X', policy_name + '_NAT'], shell = False)
		res, err = out.communicate()
		# d_Table.refresh()
		# index = get_nat_index(policy_name + '_NAT')
		# if index:
		# 	chain = iptc.Chain(d_Table, 'POSTROUTING')
		# 	rules = chain.rules
		# 	chain.delete_rule(rules[int(index) - 1])
		# n_Chain = iptc.Chain(d_Table, policy_name+'_NAT')
		# n_Chain.flush()
		# n_Chain.delete()
		# d_Table.commit()
		# d_Table.refresh()
	if check_existing_ipset(policy_name + '_src_addr'):
		destroy_ipset(policy_name + '_src_addr')
	if check_existing_ipset(policy_name + '_dst_addr'):
		destroy_ipset(policy_name + '_dst_addr')
	sb.Popen(['sudo', '/etc/init.d/iptables-persistant', 'save'], shell = False)


def add_entry(set_name, entry_value):
	out = sb.Popen(['sudo', 'ipset', '-A', set_name, entry_value, '--exist', 'comment', set_name], shell = False, stderr = sb.PIPE)
	res, err = out.communicate()
	if err:
		logger.debug("%s" %err)
	else:
		logger.debug('Entry with value of %s was added successfully in set %s' %(entry_value, set_name))
		sb.call('sudo ipset save > /etc/Firewall/ipsetSave.conf', shell = True)
	
	

#no one wants to call it, for now at least
# def create_list_set(set_name, values):
# 	getAllSets()
# 	sb.Popen(['sudo', 'ipset', '-N', set_name, 'list:set'], shell = False)
# 	saveFile()
# 	#sb.Popen(['/etc/ipset_save.sh'], shell = False)
# 	if values:
# 		for value in values:
# 			sb.Popen(['sudo', 'ipset', '-A', set_name, value], shell = False)


def addNatPolicy(policy_name, dst_zone, src_address_set, dst_address_set, policy_edit,
				sameName, schedule, notList, mapTo, comment, isSNat, nextNatIndex, isDnat):
	
	rule = iptc.Rule()
	#we don't create list:set here, why? because it had been created earlier in addForwardPolicy
	if src_address_set != 'any':
		SAM = rule.create_match('set')
		if sameName:
			if notList['src_address_set']:
				SAM.match_set = ['!', policy_name[1:]+'_src_addr', 'src']	
			else:
				SAM.match_set = [policy_name[1:]+'_src_addr', 'src']
		else:
			if notList['src_address']:
				SAM.match_set = ['!', policy_name+'_src_addr', 'src']	
			else:
				SAM.match_set = [policy_name+'_src_addr', 'src']
	if isDnat:
		rule.dst = dst_address_set.split(':')[0]
	elif dst_address_set != 'any':
		DAM = rule.create_match('set')
		if sameName:
			if notList['dst_address']:
				DAM.match_set = ['!', policy_name[1:]+'_dst_addr', 'dst']	
			else:
				DAM.match_set = [policy_name[1:]+'_dst_addr', 'dst']
		else:
			if notList['dst_address']:
				DAM.match_set = ['!', policy_name+'_dst_addr', 'dst']	
			else:
				DAM.match_set = [policy_name+'_dst_addr', 'dst']

	timeMatch = rule.create_match('time')
	if schedule['fromDate']:
		timeMatch.datestart = JalaliToGregorian(schedule['fromDate'])
	if schedule['toDate']:
		timeMatch.datestop = JalaliToGregorian(schedule['toDate'])
	if schedule['weekDay']:
		timeMatch.weekdays = schedule['weekDay']
	if schedule['startTime']:
		timeMatch.timestart = schedule['startTime']
	if schedule['endTime']:
		timeMatch.timestop = schedule['endTime']

	table = iptc.Table(iptc.Table.NAT)
	if isSNat:
		target = rule.create_target('SNAT')
		target.to_source = mapTo
	else:
		rule.target = iptc.Target(rule, 'MASQUERADE')

	table.refresh()

	if not table.is_chain(policy_name+'_NAT'):
		chain = table.create_chain(policy_name+'_NAT')
		for dvalue in dst_zone.split(','):
			if dvalue:
				if notList['dst_zone']:
					rule.out_interface = '!' + dvalue
				else:
					rule.out_interface = dvalue
			chain.insert_rule(rule)
		tempChain = iptc.Chain(table, 'POSTROUTING')
		tempRule = iptc.Rule()
		cmMatch = tempRule.create_match('comment')
		cmMatch.comment = comment
		tempRule.target = iptc.Target(rule, chain.name)
		if not nextNatIndex:
			#tempChain.insert_rule(tempRule, 0)
			tempChain.append_rule(tempRule)
		else:
			tempChain.insert_rule(tempRule, int(nextNatIndex) - 1)
	#cmd.Popen(['sudo', 'iptables', '-t', 'nat', '-N', policy_name+'_NAT'], shell = False)
	#cmd.Popen(['sudo', 'iptables', '-t', 'nat', '-I', 'POSTROUTING','1', '-j', policy_name+'_NAT'], shell = False)
	#chain = iptc.Chain(table, policy_name+'_NAT')
		table.commit()


def addDnatPolicy(policy_name, src_zone, dst_zone, src_address_set, dst_address_set, dst_port_set,
 				sameName, schedule, notList, publishServer, protocol, comment, nexDnatIndex):
	rule = iptc.Rule()
	rule.protocol = protocol
	print 222222222222222222222222
	print rule.protocol
	if protocol == 'TCP' or  protocol == 'UDP':
		DPM = rule.create_match('set')
		if notList['dst_service']:
			DPM.match_set = ['!', dst_port_set, 'dst-port']
		else:
			DPM.match_set = [dst_port_set, 'dst-port']

	elif protocol:
		if notList['dst_service']:
			rule.protocol = '!'+protocol
		else:
			rule.protocol = protocol

	#we don't create list:set here, why? because it had been created earlier in addForwardPolicy
	if src_address_set != 'any':
		SAM = rule.create_match('set')
		if sameName:
			if notList['src_address']:
				SAM.match_set = ['!', policy_name[1:]+'_src_addr', 'src']	
			else:
				SAM.match_set = [policy_name[1:]+'_src_addr', 'src']
		else:
			if notList['src_address']:
				SAM.match_set = ['!', policy_name+'_src_addr', 'src']	
			else:
				SAM.match_set = [policy_name+'_src_addr', 'src']

	table = iptc.Table(iptc.Table.NAT)
	target = rule.create_target('DNAT')
	target.to_destination = publishServer
	table.refresh()
	

	if dst_address_set != 'any':
		if not table.is_chain(policy_name+'_DNAT'):
			dst_sets = dst_address_set.split(",")
			if sameName:
				create_address_list(policy_name+'_dst_addr', dst_sets, policy_name[1:])
				out = sb.Popen(['sudo', 'ipset', 'swap', policy_name[1:]+'_dst_addr', policy_name+'_dst_addr'], shell = False, stderr = sb.PIPE)
				res, err = out.communicate()
				if err:
					print 'renamed!!!!!!!!!!!!!!!!'
					out = sb.Popen(['sudo', 'ipset', 'rename', policy_name+'_dst_addr', policy_name[1:]+'_dst_addr'], shell = False)
					out.communicate()
				else:
					destroy_ipset(policy_name + '_dst_addr')
			else:
				create_address_list(policy_name+'_dst_addr', dst_sets, policy_name)
		DAM = rule.create_match('set')
		temp = policy_name[1:]
		print temp
		if sameName:
			if notList['dst_address']:
				DAM.match_set = ['!', temp+'_dst_addr', 'dst']	
			else:
				DAM.match_set = [temp+'_dst_addr', 'dst']
		else:
			if notList['dst_address']:
				DAM.match_set = ['!', policy_name+'_dst_addr', 'dst']	
			else:
				DAM.match_set = [policy_name+'_dst_addr', 'dst']

	# if dst_address_set != 'any':
	# 	DAM = rule.create_match('set')
	# 	if sameName:
	# 		if notList['dst_address']:
	# 			DAM.match_set = ['!', policy_name[1:]+'_dst_addr', 'dst']	
	# 		else:
	# 			DAM.match_set = [policy_name[1:]+'_dst_addr', 'dst']
	# 	else:
	# 		if notList['dst_address']:
	# 			DAM.match_set = ['!', policy_name+'_dst_addr', 'dst']	
	# 		else:
	# 			DAM.match_set = [policy_name+'_dst_addr', 'dst']

	timeMatch = rule.create_match('time')
	if schedule['fromDate']:
		timeMatch.datestart = JalaliToGregorian(schedule['fromDate'])
	if schedule['toDate']:
		timeMatch.datestop = JalaliToGregorian(schedule['toDate'])
	if schedule['weekDay']:
		timeMatch.weekdays = schedule['weekDay']
	if schedule['startTime']:
		timeMatch.timestart = schedule['startTime']
	if schedule['endTime']:
		timeMatch.timestop = schedule['endTime']

	

	if not table.is_chain(policy_name+'_DNAT'):
		chain = table.create_chain(policy_name+'_DNAT')
		for svalue in src_zone.split(','):
			if svalue:
				if notList['src_zone']:
					rule.in_interface = '!' + svalue
				else:
					rule.in_interface = svalue

			chain.insert_rule(rule)
		tempChain = iptc.Chain(table, 'PREROUTING')
		tempRule = iptc.Rule()
		cmMatch = tempRule.create_match('comment')
		cmMatch.comment = comment
		tempRule.target = iptc.Target(rule, chain.name)
		if not nexDnatIndex:
			#tempChain.insert_rule(tempRule, 5)
			tempChain.append_rule(tempRule)
		else:
			tempChain.insert_rule(tempRule, int(nexDnatIndex) - 1)
	else:
		chain = iptc.Chain(table, policy_name+'_DNAT')
		for svalue in src_zone.split(','):
			if svalue:
				if notList['src_zone']:
					rule.in_interface = '!' + svalue
				else:
					rule.in_interface = svalue
			chain.insert_rule(rule)
	table.commit()


def addForwardPolicy(policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
					dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,
					sameName, comment, logEnable=False, ipsecFlag=False,limit="", isDnat = False,
					tcpFlag=False, udpFlag=False):
	
	rule = iptc.Rule()
	table = iptc.Table(iptc.Table.FILTER)
	if isDnat and (tcpFlag or udpFlag):
		rule.protocol = protocol
		m = iptc.Match(rule, protocol)
		m.dport = dst_port_set.split(':')[1]
		rule.add_match(m)
	elif protocol:
		if protocol == 'TCP' or  protocol == 'UDP':
			rule.protocol = protocol
			DPM = rule.create_match('set')
			if notList['dst_service']:
				DPM.match_set = ['!', dst_port_set, 'dst-port']
			else:
				DPM.match_set = [dst_port_set, 'dst-port']
		else:
			if notList['dst_service']:
				rule.protocol = '!'+protocol
			else:
				rule.protocol = protocol

	if src_address_set != 'any':
		if not table.is_chain(policy_name+'_FORWARD'):
			src_sets = src_address_set.split(",")
			if sameName:
				create_address_list(policy_name+'_src_addr', src_sets, policy_name[1:])
				out = sb.Popen(['sudo', 'ipset', 'swap', policy_name[1:]+'_src_addr', policy_name+'_src_addr'], shell = False, stderr = sb.PIPE)
				res, err = out.communicate()
				if err:
					out = sb.Popen(['sudo', 'ipset', 'rename', policy_name+'_src_addr', policy_name[1:]+'_src_addr'], shell = False)
					out.communicate()
				else:
					destroy_ipset(policy_name + '_src_addr')
			else:
				create_address_list(policy_name+'_src_addr', src_sets, policy_name)
		SAM = rule.create_match('set')
		if sameName:
			if notList['src_address']:
				SAM.match_set = ['!', policy_name[1:]+'_src_addr', 'src']	
			else:
				SAM.match_set = [policy_name[1:]+'_src_addr', 'src']
		else:	
			if notList['src_address']:
				SAM.match_set = ['!', policy_name+'_src_addr', 'src']	
			else:
				SAM.match_set = [policy_name+'_src_addr', 'src']


	elif src_GOIP:
		SGM = rule.create_match("geoip")
		if notList['src_GOIP']:
			SGM.source_country = '!'+ src_GOIP
		else:
			SGM.source_country = src_GOIP

	if isDnat:
		print dst_address_set.split(':')[0]
		rule.dst = dst_address_set.split(':')[0]

	elif dst_address_set != 'any':
		if not table.is_chain(policy_name+'_FORWARD'):
			dst_sets = dst_address_set.split(",")
			if sameName:
				create_address_list(policy_name+'_dst_addr', dst_sets, policy_name[1:])
				out = sb.Popen(['sudo', 'ipset', 'swap', policy_name[1:]+'_dst_addr', policy_name+'_dst_addr'], shell = False, stderr = sb.PIPE)
				res, err = out.communicate()
				if err:
					print 'renamed!!!!!!!!!!!!!!!!'
					out = sb.Popen(['sudo', 'ipset', 'rename', policy_name+'_dst_addr', policy_name[1:]+'_dst_addr'], shell = False)
					out.communicate()
				else:
					destroy_ipset(policy_name + '_dst_addr')
			else:
				create_address_list(policy_name+'_dst_addr', dst_sets, policy_name)
		DAM = rule.create_match('set')
		temp = policy_name[1:]
		print temp
		if sameName:
			if notList['dst_address']:
				DAM.match_set = ['!', temp+'_dst_addr', 'dst']	
			else:
				DAM.match_set = [temp+'_dst_addr', 'dst']
		else:
			if notList['dst_address']:
				DAM.match_set = ['!', policy_name+'_dst_addr', 'dst']	
			else:
				DAM.match_set = [policy_name+'_dst_addr', 'dst']
	

	elif dst_GOIP:
		DGM = rule.create_match('geoip')
		if notList['dst_GOIP']:
			DGM.destination_country = '!'+ dst_GOIP
		else:
			DGM.destination_country = dst_GOIP

	timeMatch = rule.create_match('time')
	if schedule['fromDate']:
		timeMatch.datestart = JalaliToGregorian(schedule['fromDate'])
	if schedule['toDate']:
		timeMatch.datestop = JalaliToGregorian(schedule['toDate'])
	if schedule['weekDay']:
		timeMatch.weekdays = schedule['weekDay']
	if schedule['startTime']:
		timeMatch.timestart = schedule['startTime']
	if schedule['endTime']:
		timeMatch.timestop = schedule['endTime']
	
	if limit:
		LM = rule.create_match('limit')
		LM.limit = str(limit) + '/s'

	table.refresh()
	if not table.is_chain(policy_name + '_FORWARD'):
		if policy_index == '-1':
			policy_index = get_forward_index('IMPLICIT_DROP')
		print 11111111111111111111111
		chain = table.create_chain(policy_name+'_FORWARD')
		tempChain = iptc.Chain(table, 'FORWARD')
		tempRule = iptc.Rule()
		cmMatch = tempRule.create_match('comment')
		cmMatch.comment = comment
		tempRule.target = iptc.Target(tempRule, chain.name)
		print policy_index
		tempChain.insert_rule(tempRule, int(policy_index) - 1)

	else:
		chain = iptc.Chain(table, policy_name+'_FORWARD')
	for svalue in src_zone.split(','):
		for dvalue in dst_zone.split(','):
			if svalue:
				print svalue
				if notList['src_zone']:
					rule.in_interface = '!' + svalue
				else:
					rule.in_interface = svalue

			if dvalue:
				print dvalue
				if notList['dst_zone']:
					rule.out_interface = '!' + dvalue
				else:
					rule.out_interface = dvalue
			if logEnable:
				logTarget = rule.create_target('LOG')
				logTarget.log_prefix = comment + ' '
				if ipsecFlag:
					inL_ipsec = rule.create_match('policy')
					inL_ipsec.pol = 'ipsec'
					inL_ipsec.dir = 'in'
					chain.append_rule(rule)
					rule.remove_match(inL_ipsec)
					outL_ipsec = rule.create_match('policy')
					outL_ipsec.pol = 'ipsec'
					outL_ipsec.dir = 'out'
					chain.append_rule(rule)
					rule.remove_match(outL_ipsec)
				else:
					chain.append_rule(rule)

			rule.target = iptc.Target(rule, action)
			if ipsecFlag:
				in_ipsec = rule.create_match('policy')
				in_ipsec.pol = 'ipsec'
				in_ipsec.dir = 'in'
				chain.append_rule(rule)
				rule.remove_match(in_ipsec)
				out_ipsec = rule.create_match('policy')
				out_ipsec.pol = 'ipsec'
				out_ipsec.dir = 'out'
			chain.append_rule(rule)
			table.commit()

#!!!!!!!!!!! IT DOESN'T HAVE GOIPPPPPPPPPPP but it has now ^^
def add_policy(new_policy_name, old_policy_name, src_zone, dst_zone, src_address_set, dst_address_set, src_port_set,
						  dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, status, mapTo="",
						  publishServer = "", policy_index ='-1',isNat=False,comment="",
							isSnat=False, isDnat=False, logEnable=False, limit="", ipsecFlag=False, policy_update=False,
							nextNatIndex='', nexDnatIndex = '', tcpFlag=False, udpFlag=False):
	
	isICMP = False
	isGRE = False
	isESP = False
	isAH = False
	isIGMP = False

	sameName = False
	IPSET_OBJECTS = getAllSets()
	if isDnat:
		publishServer=publishServer.replace("/32","")
		if publishServer.split(':')[1] == '0':
			publishServer = publishServer.split(':')[0]
	if isSnat:
		mapTo = mapTo.replace("/32", "")
	
	if policy_update:
		if new_policy_name == old_policy_name:
			new_policy_name = '_' + new_policy_name
			sameName = True
	if tcpFlag and isDnat and not udpFlag:
		addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, publishServer, 'tcp',
						publishServer, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
						comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
		dst_port_set = dst_port_set.split(',')[0]
		dst_port_set = dst_port_set + '_TCP'
		addDnatPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set, dst_port_set,
							sameName, schedule, notList, publishServer, "TCP", comment, nexDnatIndex)
		if isNat:
			addNatPolicy(new_policy_name, dst_zone, src_address_set, publishServer, "",
				sameName, schedule, notList, mapTo, comment, isSnat, nextNatIndex, isDnat)

	elif udpFlag and isDnat and not tcpFlag:
		addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, publishServer, 'udp',
						publishServer, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
						comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
		dst_port_set = dst_port_set.split(',')[0]
		dst_port_set = dst_port_set + '_UDP'
		addDnatPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set, dst_port_set,
							sameName, schedule, notList, publishServer, "UDP", comment, nexDnatIndex)
		if isNat:
			addNatPolicy(new_policy_name, dst_zone, src_address_set, publishServer, "",
				sameName, schedule, notList, mapTo, comment, isSnat, nextNatIndex, isDnat)
	else:
		print 'alaninjam'
		for value in dst_port_set.split(','):
			print value
			temp_name = value + '_ICMP'
			if temp_name in IPSET_OBJECTS and not isICMP:
				isICMP = True
				protocol = 'ICMP'
				dst_service = ""
				if isDnat:
					addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, publishServer,protocol,
							dst_service, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
							comment, logEnable, ipsecFlag, limit, isDnat, False, False)

					addDnatPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set, dst_service,
							sameName, schedule, notList, publishServer, protocol, comment, nexDnatIndex)
				else:
					addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
							dst_service, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
							comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
			temp_name = value + '_GRE'
			if temp_name in IPSET_OBJECTS and not isGRE:
				if not isDnat:
					isGRE = True
					protocol = 'GRE'
					dst_service = ""
					addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
								dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
								comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
					
			# temp_name = dst_port_set + '_EIGRP'
			# if temp_name in IPSET_OBJECTS:
			# 	protocol = 'EIGRP'
			# 	dst_service = ""
			# 	addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
			# 				dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
			# 				comment, logEnable, ipsecFlag, limit)
				
			# temp_name = dst_port_set + '_OSPF'
			# if temp_name in IPSET_OBJECTS:
			# 	protocol = 'OSPF'
			# 	dst_service = ""
			# 	addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
			# 				dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
			# 				comment, logEnable, ipsecFlag, limit)
				
			temp_name = value + '_IPSEC-ESP'
			if temp_name in IPSET_OBJECTS and not isESP:
				if not isDnat:
					isESP = True
					protocol = 'ESP'
					dst_service = ""
					addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
								dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
								comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
						
			temp_name = value + '_IPSEC-AH'
			if temp_name in IPSET_OBJECTS and not isAH:
				if not isDnat:
					isAH = True
					protocol = 'AH'
					dst_service = ""
					addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
								dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
								comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
					
			# temp_name = dst_port_set + '_L2TP'
			# if temp_name in IPSET_OBJECTS:
			# 	protocol = 'L2TP'
			# 	dst_service = ""
			# 	addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
			# 				dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
			# 				comment, logEnable, ipsecFlag, limit)

			temp_name = value + '_IGMP'
			if temp_name in IPSET_OBJECTS and not isIGMP:
				if not isDnat:
					isIGMP = True
					protocol = 'IGMP'
					dst_service = ""
					addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
								dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
								comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)

			temp_name = value + '_TCP'
			if temp_name in IPSET_OBJECTS:
				protocol = 'TCP'
				if tcpFlag and not udpFlag and isDnat:
					dst_service = publishServer.split(':')[1]
				else:
					dst_service = value + '_TCP'
				if ipset_members(dst_service):
					if isDnat:
						addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, publishServer,protocol,
							dst_service, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
							comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)

						addDnatPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set, dst_service,
							sameName, schedule, notList, publishServer, protocol, comment, nexDnatIndex)	
					else:
						addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
									dst_service, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
									comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)
			temp_name = value + '_UDP'
			if temp_name in IPSET_OBJECTS:
				protocol = 'UDP'
				if udpFlag and not tcpFlag and isDnat:
					dst_service = publishServer.split(':')[1]
				else:
					dst_service = value + '_UDP'
				if ipset_members(dst_service):
					if isDnat:
						addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, publishServer,protocol,
							dst_service, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
							comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)

						addDnatPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set, dst_service,
							sameName, schedule, notList, publishServer, protocol, comment, nexDnatIndex)	
					else:
						addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,protocol,
									dst_service, src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
									comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)

			if  value == 'any':
				addForwardPolicy(new_policy_name, src_zone, dst_zone, src_address_set, dst_address_set,"",
							"", src_GOIP, dst_GOIP, action, schedule, notList, policy_index,sameName,
							comment, logEnable, ipsecFlag, limit, isDnat, tcpFlag, udpFlag)

		if isNat:
			if isDnat:
				addNatPolicy(new_policy_name, dst_zone, src_address_set, publishServer, "",
					sameName, schedule, notList, mapTo, comment, isSnat, nextNatIndex, isDnat)
			else:
				addNatPolicy(new_policy_name, dst_zone, src_address_set, dst_address_set, "",
						sameName, schedule, notList, mapTo, comment, isSnat, nextNatIndex, isDnat)

	if policy_update:
		delete_policy(old_policy_name)	

		if sameName:
			out = sb.Popen(['sudo', 'iptables', '-E', new_policy_name + '_FORWARD', new_policy_name[1:] + '_FORWARD'], shell = False)
			res, err = out.communicate()
			# f_Table = iptc.Table(iptc.Table.FILTER)
			# f_Chain = iptc.Chain(f_Table, new_policy_name + '_FORWARD')
			# f_Chain.rename(new_policy_name[1:] + '_FORWARD')
			# f_Table.commit()
			#n_Table = iptc.Table(iptc.Table.NAT)
			if isDnat:
				out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-E', new_policy_name + '_DNAT', new_policy_name[1:] + '_DNAT'], shell = False)
				res, err = out.communicate()
				# chain = iptc.Chain(n_Table, new_policy_name + '_DNAT')
				# chain.rename(new_policy_name[1:] + '_DNAT')
				# n_Table.commit()
				# n_Table.refresh()
			if isNat:
				out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-E', new_policy_name + '_NAT', new_policy_name[1:] + '_NAT'], shell = False)
				res, err = out.communicate()
				# chain = iptc.Chain(n_Table, new_policy_name + '_NAT')
				# chain.rename(new_policy_name[1:] + '_NAT')
				# n_Table.commit()
				# n_Table.refresh()
			if dst_address_set == 'any' and check_existing_ipset(old_policy_name + '_dst_addr'):
				destroy_ipset(old_policy_name + '_dst_addr')
			if src_address_set == 'any' and check_existing_ipset(old_policy_name + '_src_addr'):
				destroy_ipset(old_policy_name + '_src_addr')
		else:
			if (old_policy_name + '_dst_addr'):
				destroy_ipset(old_policy_name + '_dst_addr')
			if check_existing_ipset(old_policy_name + '_src_addr'):
				destroy_ipset(old_policy_name + '_src_addr')
	sb.Popen(['sudo', '/etc/init.d/iptables-persistant', 'save'], shell = False)
	logger.debug('Policy named %s was added successfully' %new_policy_name)


def renameChain(new_policy_name, old_policy_name):
	table = iptc.Table(iptc.Table.FILTER)
	table.refresh()
	if table.is_chain(old_policy_name + '_FORWARD'):
		chain = iptc.Chain(table, old_policy_name + '_FORWARD')
		out = sb.Popen(['sudo', 'iptables', '-F', old_policy_name + '_FORWARD'], shell = False)
		res, err = out.communicate()
		if not table.is_chain(new_policy_name + '_FORWARD'):
			chain.rename(new_policy_name + '_FORWARD')
			table.commit()
			table.refresh()

	table = iptc.Table(iptc.Table.NAT)
	table.refresh()
	if table.is_chain(old_policy_name + '_NAT'):
		chain = iptc.Chain(table, old_policy_name + '_NAT')
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-F', old_policy_name + '_NAT'], shell = False)
		res, err = out.communicate()
		if not table.is_chain(new_policy_name + '_NAT'):
			chain.rename(new_policy_name + '_NAT')
			table.commit()
			table.refresh()
	
	if table.is_chain(old_policy_name + '_DNAT'):
		chain = iptc.Chain(table, old_policy_name + '_DNAT')
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-F', old_policy_name + '_DNAT'], shell = False)
		res, err = out.communicate()
		if not table.is_chain(new_policy_name + '_DNAT'):
			chain.rename(new_policy_name + '_DNAT')
			table.commit()
			table.refresh()
	if check_existing_ipset(old_policy_name + '_src_addr'):
		destroy_ipset(old_policy_name + '_src_addr')

	if check_existing_ipset(old_policy_name + '_dst_addr'):
		destroy_ipset(old_policy_name + '_dst_addr')
	sb.Popen(['sudo', '/etc/init.d/iptables-persistant', 'save'], shell = False)
	# readFile()
	# rule = iptc.Rule()
	# if src_zone:
	# 	if notList['src_zone']:
	# 		rule.in_interface = '!' + src_zone
	# 	else:
	# 		rule.in_interface = src_zone

	# if dst_zone:
	# 	if notList['dst_zone']:
	# 		rule.out_interface = '!' + dst_zone
	# 	else:
	# 		rule.out_interface = dst_zone
		
		
	# if src_address_set and not isDnat:
	# 	src_sets = src_address_set.split(",")
	# 	create_address_list(policy_name+'_src_address', src_sets, policy_update)
	# 	SAM = rule.create_match("set")
	# 	if notList['src_address']:
	# 		SAM.match_set = ['!', policy_name+'_src_address', 'src']	
	# 	else:
	# 		SAM.match_set = [policy_name+'_src_address', 'src']

	# if src_GOIP:
	# 	SGM = rule.create_match("geoip")
	# 	if notList['src_GOIP']:
	# 		SGM.source_country = '!'+ src_GOIP
	# 	else:
	# 		SGM.source_country = src_GOIP

	# if dst_address_set and not isNat:
	# 	dst_sets = dst_address_set.split(",")
	# 	create_address_list(policy_name+'_dst_address', dst_sets, policy_update)
	# 	DAM = rule.create_match("set")
	# 	if notList['dst_address']:
	# 		DAM.match_set = ['!', policy_name+'_dst_address', 'dst']	
	# 	else:
	# 		DAM.match_set = [policy_name+'_dst_address', 'dst']

	# elif dst_GOIP:
	# 	DGM = rule.create_match("geoip")
	# 	if notList['dst_GOIP']:
	# 		DGM.destination_country = '!'+ dst_GOIP
	# 	else:
	# 		DGM.destination_country = dst_GOIP


	# if src_port_set and not (isDnat or isNat):
	# 	src_sets = src_port_set.split(",")
	# 	create_src_service(policy_name+'_src_service', src_sets, policy_update)
	# 	SPM = rule.create_match("set")
	# 	if notList['src_service']:
	# 		SPM.match_set = ['!', policy_name+'_src_service', 'src-port']
	# 	else:
	# 		SPM.match_set = [policy_name+'_src_service', 'src-port']

	# timeMatch = rule.create_match("time")
	# if schedule['fromDate']:
	# 	timeMatch.datestart = JalaliToGregorian(schedule['fromDate'])
	# if schedule['toDate']:
	# 	timeMatch.datestop = JalaliToGregorian(schedule['toDate'])
	# if schedule['weekDay']:
	# 	timeMatch.weekdays = JalaliToGregorian(schedule['weekDay'])
	# if schedule['startTime']:
	# 	timeMatch.timestart = JalaliToGregorian(schedule['startTime'])
	# if schedule['endTime']:
	# 	timeMatch.timestop = JalaliToGregorian(schedule['endTime'])

	# if limit:
	# 	LM = rule.create_match("limit")
	# 	Lm.limit = limit + "/s"
	# #POSTROUTING
	# if isNat:
	# 	chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
	# 	target = rule.create_target("MASQUERADE")
	# 	cmMatchN = rule.create_match("comment")
	# 	cmMatchN.comment = comment + '_NAT'
	# 	if force_update and get_nat_index(policy_name):
	# 		chain.replace_rule(rule, int(get_nat_index(policy_name)))
	# 	else:
	# 		chain.insert_rule(rule)
	# elif get_nat_index(policy_name + '_NAT') and force_update:
	# 	sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', get_nat_index(policy_name)], shell = False)

	# elif isSnat:
	# 	chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
	# 	target = rule.create_target("SNAT")
	# 	target.to_source = mapTo
	# 	cmMatchS = rule.create_match("comment")
	# 	cmMatchS.comment = comment + '_SNAT'
	# 	if force_update and get_nat_index(policy_name):
	# 		chain.replace_rule(rule, int(get_nat_index(policy_name)))
	# 	else:
	# 		chain.insert_rule(rule)
	# elif get_nat_index(policy_name + '_SNAT') and force_update:
	# 	sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', get_nat_index(policy_name)], shell = False)

	# flag = False
	# if isDnat:
	# 	d_Table = iptc.Table(iptc.Table.NAT)
	# 	if get_publish_index(policy_name) and force_update:
	# 		flag = True
	# 		d_Chain = iptc.Chain(d_Table, policy_name+'_DNAT')
	# 		index = get_publish_index(policy_name)
	# 		sb.Popen(['sudo', 'iptables', '-t', 'nat', '-R', 'PREROUTING', index, '-j', d_Chain.name, '-m', 'comment', '--comment', comment], shell = False)
	# 	elif policy_update:
	# 		d_Chain = iptc.Chain(d_Table, policy_name+'_DNAT')
	# 	else:
	# 		d_Chain = d_Table.create_chain(policy_name + '_DNAT')
	# 		sb.Popen(['sudo', 'iptables', '-t', 'nat', '-I', 'PREROUTING', '1', d_Chain.name, '-m', 'comment', '--comment', comment], shell = False)
	# 	policy_final_step(dst_port_set, policy_name, notList, d_Chain, rule, flag, logEnable, comment, "", to_destination)
	# elif get_publish_index(policy_name) and force_update:
	# 	sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', get_publish_index(policy_name)], shell = False)
	
	# flag = False
	# if policy_index == -1:
	# 	policy_index = get_forward_index('IMPLICIT_DROP')
	# f_Table = iptc.Table(iptc.Table.FILTER)
	# if not force_update:
	# 	f_Chain = ""
	# 	f_Chain = f_Table.create_chain(policy_name + '_FORWARD')
	# 	sb.Popen(['sudo', 'iptables', '-I', 'FORWARD', policy_index, '-j', f_Chain.name, '-m', 'comment', '--comment', comment], shell = False)
	# elif policy_update:
	# 	f_Chain = iptc.Chain(f_Table, policy_name+'_FORWARD')
	# else:
	# 	flag = True
	# 	index = get_forward_index(policy_name)
	# 	f_Chain = iptc.Chain(f_Table, policy_name+'_FORWARD')
	# 	sb.Popen(['sudo', 'iptables', '-R', 'FORWARD', index, '-j', f_Chain.name, '-m', 'comment', '--comment', comment], shell = False)
	# policy_final_step(dst_port_set, policy_name, notList, f_Chain, rule, flag, logEnable, comment, action, "")



	


#it is called when updating policies, list:sets which were created for adding policy have to be deleted



# def create_src_service(set_name, src_port_set, policy_update):
# 	tempList = []
# 	for value in src_port_set:
# 		temp = value + '_TCP'
# 		if temp in IPSET_OBJECTS:
# 			tempList.append(temp)
# 		temp = value + '_UDP'
# 		print temp
# 		if temp in IPSET_OBJECTS:
# 			tempList.append(temp)

# 	if set_name not in IPSET_OBJECTS or policy_update:
# 		if not policy_update:
# 			create_unranged_ipset(set_name, "list:set")
# 		for value in tempList:
#    			sb.Popen(['sudo', 'ipset', '-A', set_name, value])
	
# 	else:
# 		ipsets = ipset_members(set_name)
# 		for value in tempList:
#    			sb.Popen(['sudo', 'ipset', '-A', set_name, value])
#    		for value in ipsets:
#    			sb.Popen(['sudo', 'ipset', 'del', value], shell = False)




def create_address_list(set_name, address_set, comment):
	create_unranged_ipset(set_name, "list:set")
	for value in address_set:
			sb.Popen(['sudo', 'ipset', '-A', set_name, value, 'comment', comment])

#it returns memebers of an scpeial ipset
def ipset_members(set_name):
	out = sb.Popen(['sudo', 'ipset_list', '-i', set_name], shell = False, stdout = sb.PIPE, stderr = sb.PIPE)
	res,err = out.communicate()
	if res:
		return True
	else:
		return False
#it adds a policy using group of sets
#it adds a policy using group of sets
# def add_policy(policy_name, src_zone, dst_zone, src_address_set, dst_address_set, src_port_set,
#						   dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList,old_policy_name="", mapTo="",
#						   publishServer = "", policy_index = -1,isNat=False, isMasq=False,
#							 isSnat=False, isDnat=False, logEnable=False, limit="", force_update=False):
	
#	 try:
#		 res = " "
#		 Nat_res = ""
#		 Snat_res = ""
#		 Dnat_res = ""
#		 if src_zone and not isNat:
#			 if notList['src_zone']:
#				 res += '! '
#			 res += '-i ' + src_zone + ' '
	  
#		 if dst_zone and not isDnat:
#			 if notList['dst_zone']:
#				 res += '! '
#			 res += '-o ' + dst_zone + ' '

#		 if src_address_set and not isDnat:
#			 src_sets = src_address_set.split(",")
#			 create_list_set(policy_name + '_src_address', src_sets)
#			 res += '-m set '
#			 if notList['src_address']:
#				 res += '! '
#			 res += '--match-set ' + policy_name + '_src_address ' + ' src '

#		 elif src_GOIP and not (isDnat or isNat):
#			 res += '-m set '
#			 create_list_set(policy_name + "_src_GOIP", src_GOIP)
#			 if notList['src_GOIP']:
#				 res += '! '
#			 res += '--match-set ' + policy_name + "_src_GOIP" + ' src '

#		 if dst_address_set and not isNat:
#			 res += '-m set '
#			 if notList['dst_address']:
#				 res += '! '
#			 res += '--match-set ' + dst_address_set + ' dst '
#		 elif dst_GOIP and not(isNat or isDnat):
#			 res += '-m set '
#			 create_list_set(policy_name + "_dst_GOIP", dst_GOIP)
#			 if notList['dst_GOIP']:
#				 res += '! '
#			 res += '--match-set ' + policy_name + "_dst_GOIP" + ' dst '

#		 if src_port_set and not (isDnat or isNat):
#			 create_src_service(policy_name, src_port_set)
#			 res += '-m set '
#			 if notList['src_service']:
#				 res += '! '
#			 res += '--match-set ' + policy_name + "_src_service" + ' src-port '


#		 res += ' -m time '


#		 if schedule['fromDate']:
#			 res += '--datestart ' + JalaliToGregorian(schedule['fromDate']) + ' '
#		 if schedule['toDate']:
#			 res += '--datestop ' + JalaliToGregorian(schedule['toDate']) + ' '
#		 if schedule['weekDay']:
#			 res += '--weekdays ' + schedule['weekDay'] + ' '
#		 if schedule['startTime']:
#			 res += '--timestart ' + schedule['startTime'] + ' '
#		 if schedule['endTime']:
#			 res += '--timestop' + schedule['endTime'] + ' '


#		 if isMasq:
#			 Nat_res = "sudo iptables -t nat -A POSTROUTING -j MASQUERADE " + res[:]
#			 if force_update:
#				 edit_policy(policy_name, Nat_res, 2)
#			 else:
#				 out = sb.call(shlex.split(Nat_res), shell = False, stderr = sb.PIPE)
#				 if out:
#					 logger.debug("Problem code %d occured while adding {%s}" %(out,Nat_res))
#				 else:
#					 logger.debug("{%s} was added successfully" %Nat_res)
   
		
#		 elif isSnat:
#			 Dnat_res = ""
#			 Snat_res = "sudo iptables -t nat -A POSTROUTING -j SNAT --to "+ mapTo + " " + res[:]
#			 if force_update:
#				 edit_policy(policy_name, Snat_res, 2)
#			 else:
#				 out = sb.call(shlex.split(Snat_res), shell = False, stderr = sb.PIPE)
#				 if out:
#					 logger.debug("Problem code %d occured while adding {%s}" %(out,Snat_res))
#				 else:
#					 logger.debug("{%s} was added successfully" %Snat_res)

#		 if isDnat:
#			 if (force_update and policy_name != old_policy_name) or not force_update:
#				 out = sb.Popen(['sudo', 'iptables', '-N', policy_name+'_Publish'], shell = False)
#				 err = out.communicate()
#				 if err[1]:
#					 logger.debug("There was a problem while creating %s, probably it is already exists" % (policy_name + '_Publish'))
#				 else:
#					 logger.debug("Chain named %s was created successfully" %(policy_name + "_Publish"))
#			 else:
#				 if check_existing_chain(old_policy_name + '_Publish'):
#					 out = sb.Popen(['sudo', 'iptables', '--rename-chain', old_policy_name+'_Publish', policy_name+'_Publish'], shell = False)	
#					 if out:
#						 logger.debug("There was a problem while renaming policy %s to %s"%(old_policy_name, policy_name))
#					 else:
#						 logger.debug("Policy named %s was successfully changed to %s" %(old_policy_name, policy_name))
#				 else:
#					 out = sb.Popen(['sudo', 'iptables', '-N', policy_name+'_Publish'], shell = False)
#					 err = out.communicate()
#					 if err[1]:
#						 logger.debug("There was a problem while creating %s, probably it is already exists" % (policy_name + '_Publish'))
#					 else:
#						 logger.debug("Chain named %s was created successfully" %(policy_name + "_Publish"))


#			 Dnat_res = "sudo iptables -t nat -A " + policy_name + "_Publish -j DNAT --to " + publishServer + ' ' + res[:]
#			 command = "sudo iptables -t nat -A PREROUTING " + " -j " + policy_name + "_Publish "
#			 sb.call(shlex.split(command), shell = False, stderr = sb.PIPE)
			


#		 if policy_index == -1:
#			 policy_index = get_forward_index('IMPLICIT_DROP')
#		 out = sb.Popen(['sudo', 'iptables', '-N', policy_name+'_FORWARD'], shell = False)
#		 err = out.communicate()
#		 if err[1]:
#			 logger.debug("There was a problem while creating %s, probably it is already exists" % (policy_name + '_FORWARD'))
#		 else:
#			 logger.debug("Chain named %s was created successfully" %(policy_name + "_FORWARD"))
#		 command = "sudo iptables -I FORWARD " + str(policy_index) + " -j " + policy_name + "_FORWARD "

#		 if logEnable and limit:
#			 command += '-j log --log-prefix ' + policy_name + '_FORWARD  -m limit --limit ' + limit
#		 elif logEnable:
#			 command += '-j log --log-prefix ' + policy_name + '_FORWARD '
#		 elif limit:
#			 command += ' -m limit --limit ' + limit
#		 sb.check_call(shlex.split(command), stderr = sb.PIPE)

#		 res = 'sudo iptables -A ' + policy_name + '_FORWARD ' + ' -j ' + action  + ' ' + res[:]


#		 edit_list = policy_final_step(dst_port_set, isNat, notList, res, policy_name +'_FORWARD', policy_index)
#		 if force_update:
#			 edit_policy(policy_name, edit_list, 0) 
#		 if Nat_res:
#			edit_list = policy_final_step(dst_port_set, isNat, notList, Nat_res, policy_name + '_Nat')
#			if force_update:
#				 edit_policy(policy_name, edit_list, 2) 
#		 elif force_update:
#			 index = get_nat_index(old_policy_name)
#			 if index:
#				 sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', str(index)])
#		 if Snat_res:
#			 edit_list = policy_final_step(dst_port_set, isNat, notList, Snat_res, policy_name + '_Snat')
#			 if force_update:
#				 edit_policy(policy_name, edit_list, 2) 
#		 elif force_update:
#			 index = get_nat_index(old_policy_name)
#			 if index:
#				 sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', str(index)])
#		 if Dnat_res:
#			 edit_list = policy_final_step(dst_port_set, isNat, notList, Dnat_res, policy_name + '_Publish')
#			 if force_update:
#				 edit_policy(policy_name, edit_list, 1) 
#		 elif force_update:
#			 index = get_nat_index(old_policy_name)
#			 if index:
#				 sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', str(index)], shell = False)
#				 sb.Popen(['sudo', 'iptables', '-X', policy_name+'_Publish'], shell = False)

#	 except Exception as e:
#		 print e.args
#		 print e



# def policy_final_step(dst_port_set, policy_name, notList, chain, rule, flag, logEnable, comment, action, to_destination):
# 	isICMP = False
# 	isGRE = False
# 	isEIGRP = False
# 	isOSPF = False
# 	isESP = False
# 	isAH = False
# 	isL2TP = False
# 	isIGMP = False
# 	number = 0
# 	counter = 0
# 	if flag and action:
# 		number = 1
# 		counter = count_forward_rules(policy_name)
# 	elif flag and to_destination:
# 		number = 1
# 		counter = count_dnat_rules(policy_name)
# 	try:
# 		if dst_port_set:
# 			if flag:
# 				tcp_ipsets = ipset_members(policy_name+'_TCP')
# 				udp_ipsets = ipset_members(policy_name+'_UDP')

# 			list_ports = dst_port_set.split(",")
# 			print IPSET_OBJECTS
# 			for value in list_ports:
# 				temp_name = value + "_TCP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					create_list_set(policy_name+'_TCP', temp_name.split())	

# 				temp_name = value + "_UDP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					create_list_set(policy_name+'_UDP', temp_name.split())

# 				temp_name = value + "_ICMP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isICMP = True

# 				temp_name = value + "_GRE" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isGRE = True

# 				temp_name = value + "_EIGRP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isEIGRP = True

# 				temp_name = value + "_OSPF" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isOSPF = True

# 				temp_name = value + "_IPSEC-ESP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isESP = True

# 				temp_name = value + "_IPSEC-AH" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isAH = True

# 				temp_name = value + "_L2TP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isL2TP = True

# 				temp_name = value + "_IGMP" #each value represents an object
# 				if temp_name in IPSET_OBJECTS:
# 					isIGMP = True
# 				continue

# 			DPM = rule.create_match("set")

# 			temp_name = policy_name + "_TCP"
# 			if temp_name in IPSET_OBJECTS:
# 				rule.protocol = "tcp"
# 				DPM.reset()
# 				if notList['dst_service']:
# 					DPM.match_set = ['!', temp_name, 'dst-port']
# 				else:
# 					DPM.match_set = [temp_name, 'dst-port']
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 			temp_name = policy_name + "_UDP"
# 			if temp_name in IPSET_OBJECTS:
# 				rule.protocol = "udp"
# 				DPM.reset()
# 				if notList['dst_service']:
# 					DPM.match_set = ['!', temp_name, 'dst-port']
# 				else:
# 					DPM.match_set = [temp_name, 'dst-port']
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 			if isICMP:
# 				if notList['dst_service']:
# 					rule.protocol = "!icmp"
# 				else:
# 					rule.protocol = "icmp"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)


# 			if isGRE:
# 				if notList['dst_service']:
# 					rule.protocol = "!gre"
# 				else:
# 					rule.protocol = "gre"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)


# 			if isEIGRP:
# 				if notList['dst_service']:
# 					rule.protocol = "!eigrp"
# 				else:
# 					rule.protocol = "eigrp"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 			if isOSPF:
# 				if notList['dst_service']:
# 					rule.protocol = "!ospf"
# 				else:
# 					rule.protocol = "ospf"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)


# 			if isESP:
# 				if notList['dst_service']:
# 					rule.protocol = "!esp"
# 				else:
# 					rule.protocol = "esp"
# 				DPM.reset()	
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)


# 			if isAH:
# 				if notList['dst_service']:
# 					rule.protocol = "!ah"
# 				else:
# 					rule.protocol = "ah"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 			if isL2TP:
# 				if notList['dst_service']:
# 					rule.protocol = "!l2tp"
# 				else:
# 					rule.protocol = "l2tp"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 			if isIGMP:
# 				if notList['dst_service']:
# 					rule.protocol = "!igmp"
# 				else:
# 					rule.protocol = "igmp"
# 				DPM.reset()
# 				policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 		else:
# 			policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter)

# 		if counter > number:
# 			if action:				
# 				for i in range(number+1, counter+1):
# 					sb.Popen(['sudo', 'iptables', '-D', policy_name+'_FORWARD', str(i)], shell = False)
# 			else:
# 				for i in range(number+1, counter+1):
# 					sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', policy_name+'_DNAT', str(i)], shell = False)

# 	except Exception as e:
# 		print e

# 	else:
# 		#sb.Popen(['/etc/iptables_save.sh'], shell = False)
# 		logger.debug('Policy named %s was successully created' %(policy_name))


# def policy_insert(logEnable, comment, chain, rule, to_destination, action, flag, number, counter):
# 	if logEnable:
# 		logTarget = rule.create_target("LOG")
# 		logTarget.log_prefix = comment
# 		if flag:
# 			if number <= counter:
# 				chain.replace_rule(rule, number)
# 				number = number + 1
# 			else:
# 				chain.append_rule(rule)
# 		else:
# 			chain.append_rule(rule)
# 	if to_destination:
# 		d_Target = rule.create_target("DNAT")
# 		d_Target.to_destination = to_destination
# 		if flag:
# 			if number <= counter:
# 				chain.replace_rule(rule, number)
# 				number = number + 1
# 			else:
# 				chain.append_rule(rule)
# 		else:
# 			chain.append_rule(rule)
# 	elif action:
# 		f_Target = rule.create_target(action)
# 		if flag:
# 			if number <= counter:
# 				chain.replace_rule(rule, number)
# 				number = number + 1
# 			else:
# 				chain.append_rule(rule)
# 		else:
# 			chain.append_rule(rule)


def count_forward_rules(policy_name):
	out = sb.Popen(['sudo', 'iptables', '-L', policy_name + '_FORWARD'], shell = False, stdout = sb.PIPE)
	result = out.communicate()
	splited_by_BN = result.split("\n")
	return len(splited_by_BN) - 3

def count_dnat_rules(policy_name):
	out = sb.Popen(['sudo', 'iptables', '-L', policy_name + '_DNAT'], shell = False, stdout = sb.PIPE)
	result = out.communicate()
	splited_by_BN = result.split("\n")
	return len(splited_by_BN) - 3



# def edit_policy(policy_name, policies, flag):
# 	#FORWARD CHAIN 
# 	if flag == 0:
# 		out = sb.Popen(['sudo', 'iptables', '-L', policy_name + '_FORWARD'], shell = False, stdout = sb.PIPE)
# 		result = out.communicate()
# 		splited_by_BN = result.split("\n")
# 		size = len(policy_name) + 25
# 		i = 0
# 		for i in range(0,len(splited_by_BN) - 3):
# 			policies[i] = policies[i][size:]
# 			sb.Popen(['sudo', 'iptables', '-R', policy_name+'_FORWARD', str(i+1), policies[i]])
# 		if i < len(policies) -1:
# 			for i in range (i+1,len(policies)):
# 				sb.call(shlex.split(policies[i]), shell = False)
# 		if len(splited_by_BN) - 3 > len(policies):
# 			for j in range(len(policies) + 1, len (splited_by_BN) - 2):
# 				sb.Popen(['sudo', 'iptables', '-D', policy_name+'_FORWARD', str(j)], shell = False)

# 	#PREROUTING
# 	elif flag == 1:
# 		out = sb.Popen(['sudo', 'iptables', '-L', policy_name + '_Publish'], shell = False, stdout = sb.PIPE)
# 		result = out.communicate()
# 		size = len(policy_name) + 32
# 		splited_by_BN = result.split("\n")
# 		for i in range(0,len(policies)):
# 			policies[i] = policies[i][size:]
# 			sb.Popen(['sudo', 'iptables', '-R', policy_name+'_Publish', str(i+1), policies[i]])

# 		if len(splited_by_BN) - 3 > len(policies):
# 			for i in range(len(policies) + 1, len (splited_by_BN) - 2):
# 				sb.Popen(['sudo', 'iptables', '-D', policy_name+'_Publish', str(i)], shell = False)

# 	#NAT
# 	elif flag == 2:
# 		index = get_nat_index(policy_name)
# 		if index:
# 			policies = policies[35:]
# 			sb.Popen(['sudo', 'iptables', '-t', 'nat', '-R', 'POSTROUTING', index, policies[0]], shell = False)
# 		else:
# 			out = sb.call(shlex.split(policies), shell = False, stderr = sb.PIPE)
# 			if out:
# 				logger.debug("Problem code %d occured while adding {%s}" %(out,policies))
# 			else:
# 				logger.debug("{%s} was added successfully" %policies)
   



#it will get the index of the given line
def get_forward_index(policy_name):
	try:
		first = sb.Popen(['sudo', 'iptables', '-nvL', 'FORWARD', '--line-numbers'], stdout=sb.PIPE, shell=False)
		second = sb.Popen(['grep', '-w', policy_name], stdin = first.stdout, stdout = sb.PIPE, shell = False)
		result,err = second.communicate()
		index = ""
		if result:
			i = 0
			while result[i] != " ":
				index  = index + result[i]
				i = i + 1
	except Exception as e:
		print e
		logger.debug(e)
	else:
		if index:
			logger.debug("Policy named %s was found at chain FORWARD in line %s" %(policy_name, index))
		else:
			logger.debug("Policy named %s was not found at chain FORWARD" %(policy_name))
		return index


#just POSTROUTING
def get_nat_index(policy_name):
	try:
		first = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-nvL', 'POSTROUTING', '--line-numbers'], stdout=sb.PIPE, shell=False)
		second = sb.Popen(['grep', '-w', policy_name], stdin = first.stdout, stdout = sb.PIPE, shell = False)
		result,err = second.communicate()
		index = ""
		if result:
			i = 0
			while result[i] != " ":
				index  = index + result[i]
				i = i + 1
	except Exception as e:
		print type(e)
		print e.args
		print e
		logger.debug(e)
	else:
		if index:
			logger.debug("Policy named %s was found at chain POSTROUTING in line %s" %(policy_name, index))
		else:
			logger.debug("Policy named %s was not found at chain POSTROUTING" %(policy_name))
		return index
#just PREROUTING
def get_publish_index(policy_name):
	try:
		first = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-nvL', 'PREROUTING', '--line-numbers'], stdout=sb.PIPE, shell=False)
		second = sb.Popen(['grep', '-w', policy_name], stdin = first.stdout, stdout = sb.PIPE, shell = False)
		result,err = second.communicate()
		print result
		index = ""
		if result:
			i = 0
			while result[i] != " ":
				index  = index + result[i]
				i = i + 1
	except Exception as e:
		print type(e)
		print e.args
		print e
		logger.debug(e)
	else:
		if index:
			logger.debug("Policy named %s was found at chain PREROUTING in line %s" %(policy_name, index))
		else:
			logger.debug("Policy named %s was not found at chain PREROUTING" %(policy_name))
		return index



#creating ip-range, does the type have to be hash:ip?
#NOTE: Is the directory fine? && shell = True!!!!!
# def add_iprange(set_name, range_ip, comment=""):
#	 print "------------------------------------range_ip-----------------------"
#	 print range_ip
#	 if comment:
#		 comment = "(" + set_name + ") " + "_" + comment
#	 else:
#		 comment = "(" + set_name + ")"
#	 RESULTS = []
#	 list_ip = range_ip.split(",")
#	 for i in range (0,len(list_ip)):
#		 temp = list_ip[i].split("-")
#		 if len(temp) > 1:
#			 start = temp[0].split(".")
#			 stop = temp[1].split(".")
#			 for j in range(int(start[3]), int(stop[3])+1):
#				 ip = start[0] + "." + start[1] + "." + start[2] + "." + str(j)
#				 if not ip in RESULTS:
#					 RESULTS.append(str(ip))
#		 else:
#			 if temp[0] not in RESULTS:
#				 RESULTS.append(temp[0])

#	 myFile = open ("/tmp/tmp.conf", 'w')
#	 for value in RESULTS:
#		 myFile.write('add %s %s comment %s\n' %(set_name, value, comment))
#	 myFile.close()
#	 sb.call(["sudo ipset restore < /tmp/tmp.conf"], shell = True)
#	 sb.call(["sudo ipset save > /tmp/ipset_backup.conf"], shell = True)
#	 logger.debug("Entry %s was added in set %s successully" %(range_ip, set_name))
#	 return


#it is used for adding a range of ports to an special set
def add_portrange(set_name, ports):
	IPSET_OBJECTS = getAllSets()
	TCP_List = []
	UDP_List = []

	list_ports = ports.split(":")
	for i in range(0,len(list_ports)):
		if list_ports[i][:3] == 'tcp':
			list_ports[i] = list_ports[i][4:]
			val_ports = list_ports[i].split(",")
			for port in val_ports :
				if (set_name + '_TCP') not in IPSET_OBJECTS:
					create_bitmap_port_ipset(set_name + '_TCP')
					IPSET_OBJECTS.append(set_name + '_TCP')
				add_entry(set_name + '_TCP', port)
		elif list_ports[i][:3] == 'udp' :
			list_ports[i] = list_ports[i][4:]
			val_ports = list_ports[i].split(",")
			for port in val_ports :
				if (set_name + '_UDP') not in IPSET_OBJECTS:
					create_bitmap_port_ipset(set_name + '_UDP')
					IPSET_OBJECTS.append(set_name + '_UDP')
				add_entry(set_name + '_UDP', port)

		elif list_ports[i] == "ICMP":
			temp_name = set_name + "_ICMP"
			if temp_name not in IPSET_OBJECTS:
				sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
				IPSET_OBJECTS.append(temp_name)
				logger.debug("IPSet %s was created successully" % temp_name)
			else:
				logger.debug("Set with %s already exists" %set_name)

		elif list_ports[i] == "GRE":
			temp_name = set_name + "_GRE"
			if temp_name not in IPSET_OBJECTS:
				sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
				IPSET_OBJECTS.append(temp_name)
				logger.debug("IPSet %s was created successully" % temp_name)
			else:
				logger.debug("Set with %s already exists" %set_name)

		# elif list_ports[i] == "EIGRP":
		# 	temp_name = set_name + "_EIGRP"
		# 	if temp_name not in IPSET_OBJECTS:
		# 		sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
		# 		IPSET_OBJECTS.append(temp_name)
		# 		logger.debug("IPSet %s was created successully" % temp_name)
		# 	else:
		# 		logger.debug("Set with %s already exists" %set_name)
		
		# elif list_ports[i] == "OSPF":
		# 	temp_name = set_name + "_OSPF"
		# 	if temp_name not in IPSET_OBJECTS:
		# 		sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
		# 		IPSET_OBJECTS.append(temp_name)
		# 		logger.debug("IPSet %s was created successully" % temp_name)
		# 	else:
		# 		logger.debug("Set with %s already exists" %set_name)
		
		elif list_ports[i] == "IPSEC-ESP":
			temp_name = set_name + "_IPSEC-ESP"
			if temp_name not in IPSET_OBJECTS:
				sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
				IPSET_OBJECTS.append(temp_name)
				logger.debug("IPSet %s was created successully" % temp_name)
			else:
				logger.debug("Set with %s already exists" %set_name)
		
		elif list_ports[i] == "IPSEC-AH":
			temp_name = set_name + "_IPSEC-AH"
			if temp_name not in IPSET_OBJECTS:
				sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
				IPSET_OBJECTS.append(temp_name)
				logger.debug("IPSet %s was created successully" % temp_name)
			else:
				logger.debug("Set with %s already exists" %set_name)
		
		# elif list_ports[i] == "L2TP":
		# 	temp_name = set_name + "_L2TP"
		# 	if temp_name not in IPSET_OBJECTS:
		# 		sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
		# 		IPSET_OBJECTS.append(temp_name)
		# 		logger.debug("IPSet %s was created successully" % temp_name)
		# 	else:
		# 		logger.debug("Set with %s already exists" %set_name)

		elif list_ports[i] == "IGMP":
			temp_name = set_name + "_IGMP"
			if temp_name not in IPSET_OBJECTS:
				sb.Popen(['sudo', 'ipset', '-N', temp_name, 'bitmap:port', 'range', '0-0'])
				IPSET_OBJECTS.append(temp_name)
				logger.debug("IPSet %s was created successully" % temp_name)
			else:
				logger.debug("Set with %s already exists" %set_name)
		

		else:
			if list_ports[i] in tcp_port_list:
				tcp_ports = tcp_port_list[list_ports[i]].split("/")
				for j in range(0,len(tcp_ports)):
					if (set_name + '_TCP') not in IPSET_OBJECTS:
						create_bitmap_port_ipset(set_name + '_TCP')
					add_entry(set_name + '_TCP', tcp_ports[j])

			if list_ports[i] in udp_port_list:
				udp_ports = udp_port_list[list_ports[i]].split("/")
				for j in range(0,len(udp_ports)):
					if (set_name + '_UDP') not in IPSET_OBJECTS:
						create_bitmap_port_ipset(set_name + '_UDP')
					add_entry(set_name + '_UDP', udp_ports[j])
			continue
	sb.call('sudo ipset save > /etc/Firewall/ipsetSave.conf', shell = True)
	return



def policy_drag_drop(policy_name, oldIndex, newIndex, oldNatIndex, newNatIndex, oldDnatIndex, newDnatIndex):
	if newIndex:
		if int(newIndex) < int(oldIndex):
			out = sb.Popen(['sudo', 'iptables', '-I', 'FORWARD', str(newIndex), '-j', policy_name + '_FORWARD', '-m', 'comment', '--comment', policy_name], shell = False)
			out.communicate()
			out = sb.Popen(['sudo', 'iptables', '-D', 'FORWARD', str(int(oldIndex) + 1)], shell = False)
			out.communicate()
		else:
			out = sb.Popen(['sudo', 'iptables', '-I', 'FORWARD', str(int(newIndex) + 1), '-j', policy_name + '_FORWARD', '-m', 'comment', '--comment', policy_name], shell = False)
			out.communicate()
			out = sb.Popen(['sudo', 'iptables', '-D', 'FORWARD', str(oldIndex)], shell = False)
			out.communicate()
	if newNatIndex:
		if int(newNatIndex) < int(oldNatIndex):
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-I', 'POSTROUTING', str(newNatIndex), '-j', policy_name + '_NAT', '-m', 'comment', '--comment', policy_name], shell = False)
			out.communicate()
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', str(int(oldNatIndex) + 1)], shell = False)
			out.communicate()
		else:
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-I', 'POSTROUTING', str(int(newNatIndex) + 1), '-j', policy_name + '_NAT', '-m', 'comment', '--comment', policy_name], shell = False)
			out.communicate()
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', str(oldNatIndex)], shell = False)
			out.communicate()

	if newDnatIndex:
		if int(newDnatIndex) < int(oldDnatIndex):
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-I', 'PREROUTING', str(newDnatIndex), '-j', policy_name + '_DNAT', '-m', 'comment', '--comment', policy_name], shell = False)
			out.communicate()
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', str(int(oldDnatIndex) + 1)], shell = False)
			out.communicate()
		else:
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-I', 'PREROUTING', str(int(newDnatIndex) + 1), '-j', policy_name + '_DNAT', '-m', 'comment', '--comment', policy_name], shell = False)
			out.communicate()
			out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', str(oldDnatIndex)], shell = False)
			out.communicate()


def check_empty_group(group_name):
	out = sb.Popen(['sudo', 'ipset', 'list', group_name], shell = False, stdout = sb.PIPE)
	result = out.communicate()
	print "===================================result=============================="
	temp = result[0].split("Members:")
	print len(temp[0])
	if len(temp) > 0:
		if temp[1] == "\n":
			destroy_ipset(group_name)


def checkExistingFilterChain(chain_name):
	out = sb.Popen(['sudo', 'iptables', '-L', chain_name], shell = False, stdout = sb.PIPE)
	res = out.communicate()
	if res[0]:
		return True
	else:
		return False


def checkExistingNatChain(chain_name):
	out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-L', chain_name], shell = False, stdout = sb.PIPE)
	res = out.communicate()
	if res[0]:
		return True
	else:
		return False

def check_existing_ipset(set_name):
	first = sb.Popen(['sudo', 'ipset', 'list'], shell = False, stdout = sb.PIPE)
	second = sb.Popen(['grep', '-w', set_name], shell = False, stdin = first.stdout, stdout = sb.PIPE)
	result, err = second.communicate()
	if result:
		return True
	else:
		return False


def disablePolicy(policyName):
	index = get_forward_index(policyName  + '_FORWARD')
	if index:
		out = sb.Popen(['sudo', 'iptables', '-D', 'FORWARD', str(index)], shell = False)
		res, err = out.communicate()
		# table = iptc.Table(iptc.Table.FILTER)
		# chain = iptc.Chain(table, 'FORWARD')
		# rules = chain.rules
		# chain.delete_rule(rules[int(index)-1])
		# table.commit()
		# table.refresh()
	index = get_nat_index(policyName  + '_NAT')
	if index:
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', str(index)], shell = False)
		res, err = out.communicate()
		# table = iptc.Table(iptc.Table.NAT)
		# chain = iptc.Chain(table, 'POSTROUTING')
		# rules = chain.rules
		# chain.delete_rule(rules[int(index)-1])
		# table.commit()
		# table.refresh()		
	
	index = get_publish_index(policyName  + '_DNAT')
	if index:
		out = sb.Popen(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', str(index)], shell = False)
		res, err = out.communicate()
		# table = iptc.Table(iptc.Table.NAT)
		# chain = iptc.Chain(table, 'PREROUTING')
		# rules = chain.rules
		# chain.delete_rule(rules[int(index)-1])
		# table.commit()
		# table.refresh()

def deleteProtocol(setName):
	destroy_ipset(setName + "_TCP")
	destroy_ipset(setName + "_UDP")
	destroy_ipset(setName + "_ICMP")
	destroy_ipset(setName + "_IGMP")
	destroy_ipset(setName + "_GRE")
	destroy_ipset(setName + "_EIGRP")
	destroy_ipset(setName + "_OSPF")
	destroy_ipset(setName + "_IPSEC-ESP")
	destroy_ipset(setName + "_IPSEC-AH")
	destroy_ipset(setName + "_L2TP")


print "------------------------------------fwmw----------------------------"
logger = logging.getLogger('ipset')
ipset_logging_configs(logger)

#edit_entry('myset', '192.168.100.10', '192.168.10.10')
#create_ipset("set1", "iphash")

#for i in range(0,199):
#	delete_entry('set1', '192.168.1.%s' %i)

#delete_entry('set1', '192.168.10.10)

#add_entry('set1', 'set2,set3', "")

#add_portrange('setport', 'ICMP:tcp=50-100:GRE', '')
#add_single_policy_rule('www', 'eth0', str(), str(), str(), str(), str(), 'ACCEPT', True, True)
#delete_ipset('myset1')
#add_ipset_policy_rule('woerwew', 'set1', str(),'set3',str() , str(), 'DROP', True, True)
#create_ipset_iprange('set', '192.168.1.1', '192.168.1.100')
#create_ipset('myset2', 'hash:ip', False)
#add_entry('myset2', '192.168.100.10', str())
#add_portrange('porty','MS-SQL-S' )
#add_iprange('myset', '192.168.9.2-192.168.9.20', str())
#def edit_ipset(old_set_name, new_set_name, new_type, old_groupName, new_groupName, new_value, comment = str()):
#edit_ipset('addr', 'kala', 'fqdn', 'list', 'list', '192.168.2.20-192.168.2.25')

# notList={}
# notList['src_GOIP']=""
# notList['dst_GOIP']=""
# notList['src_zone']=""
# notList['dst_zone']=""
# notList['src_address']=""
# notList['dst_address']=""
# notList['src_service']=""
# notList['dst_service']=""
# schedule={}
# schedule['fromDate']=""
# schedule['toDate']=""
# schedule['weekDay']=""
# schedule['startTime']=""
# schedule['endTime']=""


# for i in range(0,10):
# 	add_policy( 'newww' + str(i), '', '', '', '', '',False,
# 						  '', '', '', 'ACCEPT', schedule, notList,comment='newww')


# def add_policy(policy_name, src_zone, dst_zone, src_address_set, dst_address_set, src_port_set,policy_update,
# 						  dst_port_set, src_GOIP, dst_GOIP, action, schedule, notList, mapTo="",
# 						  publishServer = "", policy_index = -1,isNat=False, isMasq=False,comment="",
# 							isSnat=False, isDnat=False, logEnable=False, limit="", force_update=False):


# deleteAddressSet('myset')
# deleteAddressSet('myset1')

