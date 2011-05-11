#
# openCryptoki debugging helper script
#
# Kent Yoder <yoder1@us.ibm.com>
# April 29, 2011
#
# Functions:
#
# ock_dump_obj_template <OBJECT *>
# ock_dump_object_map
# ock_dump_sess_btree
# ock_dump_sess_obj_btree
# ock_dump_priv_tok_obj_btree
# ock_dump_publ_tok_obj_btree
#

set $OBJECT_MAP = 1
set $OBJECT     = 2
set $SESSION    = 3

#
# ock_dump_obj_template <OBJECT *>
#
# Dump an OBJECT's template of attributes
#
define ock_dump_obj_template
	set $obj = ($arg0)
	set $node = $obj->template->attribute_list

	while ($node)
		print *(CK_ATTRIBUTE *)($node->data)
		set $node = $node->next
	end
end

define __ock_print_node_type
	if $arg1 == $OBJECT_MAP
		print *((OBJECT_MAP *)($arg0)->value)
	end
	if $arg1 == $OBJECT
		print *((OBJECT *)($arg0)->value)
	end
	if $arg1 == $SESSION
		print *((SESSION *)($arg0)->value)
	end
end

define __ock_print_node
	set $n = ($arg0)
	set $loc = ($arg1)

	while ($loc > 1)
		if ($loc & 1)
			set $n = $n->right
		else
			set $n = $n->left
		end

		set $loc = $loc >> 1
		printf "   "
	end

	if ($n->flags & 1)
		printf "`- %d: (deleted node)\n", $arg1
	else
		printf "`- %d: ", $arg1
		__ock_print_node_type $n $arg2
	end
end

define __ock_dump_tree
	set $size = ($arg0).size + 1
	set $i = 1

	printf "tree: size %d, free nodes: %d\n", $arg0.size, ($arg0).free_nodes
	while ($i < $size)
		__ock_print_node ($arg0).top $i ($arg1)
		set $i = $i + 1
	end
end

define ock_dump_object_map
	__ock_dump_tree object_map_btree $OBJECT_MAP
end

define ock_dump_sess_btree
	__ock_dump_tree sess_btree $SESSION
end

define ock_dump_sess_obj_btree
	__ock_dump_tree sess_obj_btree $OBJECT
end

define ock_dump_priv_tok_obj_btree
	__ock_dump_tree priv_token_obj_btree $OBJECT
end

define ock_dump_publ_tok_obj_btree
	__ock_dump_tree publ_token_obj_btree $OBJECT
end

define dump_ec_key_token
	set $tok = ($arg0)
	printf "----------------------- HEADER SECTION -----------------------\n"
	printf "Token ID: 0x%02X\n", $tok
	printf "Token Version Number: 0x%02X\n", $tok[1]
	printf "Length in bytes of token structure: 0x%02X%02X\n", $tok[2], $tok[3]
	printf "----------------------- PRIVATE SECTION -----------------------\n"
	set $priv = $tok[8]
	printf "Section ID: 0x%02X\n", $priv
	printf "\tX'20': ECC private key\n"
	printf "Section version number: 0x%02X\n", $tok[9]
	printf "Section len: 0x%02X%02X\n", $tok[10], $tok[11]
	printf "Wrapping method: 0x%02X\n", $tok[12]
	printf "\tX'00': Section is unencrypted (clear),  X'01': AESKW, X'02: CBC\n"
	printf "Hash method used for wrapping: 0x%02X\n", $tok[13]
	printf "\tX'01': SHA-224,  X'02': SHA-256\n"
	printf "Key usage: 0x%02X\n", $tok[16]
	printf "\tX'C0': Key agreement,  X'80': Both signature gen & key agreement\n"
	printf "\tX'00': Signature generation only,  X'02': Translate allowed\n"
	printf "Curve type: 0x%02X\n", $tok[17]
	printf "\tX'00': Prime curve,  X'01': Brainpool curve\n"
	printf "Key format and security flag: 0x%02X\n", $tok[18]
	printf "\tEncrypted internal ECC: X'08',  "
	printf "Unencrypted external ECC: X'40',  "
	printf "Encrypted external ECC: X'42'\n"
	printf "Length of p in bits: 0x%02X%02X\n", $tok[20], $tok[21]
	printf "\tX'00A0': Brainpool P-160\n"
	printf "\tX'00C0': Prime P-192, Brainpol P-192\n"
	printf "\tX'00E0': Brainpool P-224, Prime P-224\n"
	printf "\tX'0100': Brainpool P-256, Prime P-256\n"
	printf "\tX'0140': Brainpool P-320\n"
	printf "\tX'0180': Prime P-384, Brainpool P-384\n"
	printf "\tX'0200': Brainpool P-512\n"
	printf "\tX'0209': Prime P-521\n"
	printf "IBM associated data length in bytes: 0x%02X%02X\n", $tok[22], $tok[23]
	printf "Master key verification pattern:\n\t"
	set $i = 0
	while ($i < 8)
		printf "%02X", $tok[24+$i]
		set $i = $i+1
	end
	printf "\n"

	printf "Associated data length: 0x%02X%02X\n", $tok[80], $tok[81]
	printf "Length of formatted section in bytes: 0x%02X%02X\n", $tok[82], $tok[83]
	printf "-------- Begin formatted section (include d) data --------\n"
	set $dlen = $tok[83]
	set $assclen = $tok[81]
	set $i = 0
	while ($i < $dlen)
		printf "%02X", $tok[84+$assclen+$i]
		set $i = $i+1
	end
	printf "\n-------- End formatted section data --------\n"
	printf "----------------------- PUBLIC SECTION -----------------------\n"
	set $privlen = $tok[11]
	set $puboffset = $privlen+8
	printf "Section ID: 0x%02X\n", $tok[$puboffset]
	printf "\tX'21': ECC public key\n"
	printf "Section version number: 0x%02X\n", $tok[$puboffset+1]
	printf "Section length: 0x%02X%02X\n", $tok[$puboffset+2], $tok[$puboffset+3]
	printf "Curve type: 0x%02X\n", $tok[$puboffset+8]
	printf "\tX'00': Prime curve,  X'01': Brainpool curve\n"
	printf "Length of p in bits: 0x%02X%02X\n", $tok[$puboffset+10], $tok[$puboffset+11]
	printf "Length of public key q in bytes: 0x%02X%02X\n", $tok[$puboffset+12], $tok[$puboffset+13]
	printf "-------- Begin q data --------\n"
	set $qlen = $tok[$puboffset+13]
	set $i = 0
	while ($i < $qlen)
		printf "%02X", $tok[$puboffset+14+$i]
		set $i = $i+1
	end
	printf "\n-------- End q data --------\n"
end
document dump_ec_key_token
Print the Elliptic Curve key token generated by CSNDPKG.
end
