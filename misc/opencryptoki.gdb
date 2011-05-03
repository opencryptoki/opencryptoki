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
