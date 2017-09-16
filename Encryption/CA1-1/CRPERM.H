/* file crperm.h permutation and tree */

extern basic_apply_permutation();
extern apply_permutation();
extern SubstitutionPhase();
extern btree_recursive_type_node();
extern btree_type_node();
extern btree_assign_next_pointers();
extern btree_do_division();
extern btree_make_root();
extern tell_the_news();
extern int   btree_read();
extern tree_to_perm();
extern btree_build();



#define MAX_B_NODES  512

typedef struct bnod {
int following,level,leaf,num; /* leaf=0 is a leaf, l
only left, 2, only right , 3 both defined */

struct bnod *next[2];
struct bnod *mother;
} bnode_type, *bnode_ptr_type;

bnode_type btree[MAX_B_NODES];

int btree_node_counter,btree_perm_num;




