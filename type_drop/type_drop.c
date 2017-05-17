/****************************************************************************
 *
 * CDI PATCH: '#include'ed in c-parser.c (separated here for convenience)
 *
 ****************************************************************************/

/* A linked list for source filenames
 * This is used to tell if a ftypes or fptypes file has already been opened
 *
 * While a hash table would be faster, it's more complicated. This solution will
 * suffice for now. 99% of the time there will only be 1-2 typefiles open
 */
typedef struct LinkedList {
    char *filename;
    LinkedList *next;
} Node;

/*
 * Returns a Node* with the given filename and type info designation
 * Returns NULL if no such node exists
 */
Node *get_node(Node* head, const char *filename) {
    if (!head) {
        return NULL;
    }
    else if (!strcmp(head->filename, filename)) {
        return head;
    }
    else {
        return get_node(head->next, filename);
    }
}

/*
 * Adds a node to a linked list. Returns the head.
 * If head is NULL, then add_node creates a new linked list
 */
Node *add_node(Node* head, char *filename) {
    Node *new_node = (Node*)xmalloc(sizeof(Node));
    new_node->filename = filename;
    new_node->next = head;

    return new_node;
}

void print_node_helper(FILE *stream, const Node *head) {
    if (!head) {
        fprintf(stream, ")\n");
        return;
    }

    fprintf(stream, "%s ", head->filename);
    print_node_helper(stream, head->next);
}

void print_list(FILE *stream, const Node *head) {
    fprintf(stream, "( ");
    print_node_helper(stream, head);
}


#define CDI_ENTER() 
#define CDI_EXIT() 
//#define CDI_ENTER() printf("Entering %s:%s\n", __FILE__, __func__)
//#define CDI_EXIT()  printf("Exiting  %s:%s\n", __FILE__, __func__)

static bool cdi_function_ahead = false;

void cdi_warning_at(location_t loc, const char *msg) {
    CDI_ENTER();
    if (loc) {
        cdi_print_loc(stderr, loc);
    }
    else {
        fprintf(stderr, "-:-:-");
    }

    fprintf(stderr, ": cdi warning: %s\n", msg);
    CDI_EXIT();
}
    
void cdi_set_function_ahead(bool is_ahead) {
    CDI_ENTER();
    cdi_function_ahead = is_ahead;
    CDI_EXIT();
}

void
cdi_print_loc(FILE *stream, location_t loc) {
    CDI_ENTER();
    if (!stream) {
        return;
    }
        
    expanded_location loc_info = expand_location(loc);

    if (loc_info.file) {
        fprintf(stream, "%s:%d:%d", loc_info.file,
                loc_info.line, loc_info.column);
    }
    else {
        fprintf(stream, "?:%d:%d", loc_info.line, loc_info.column);
    }
    CDI_EXIT();
}

void cdi_print_funct_decl_info(FILE *typefile, tree funct_decl, location_t loc) {
    CDI_ENTER();
    if (!typefile) {
        CDI_EXIT();
        return;
    }
    else if (!funct_decl) {
        cdi_warning_at(loc, "cannot print signature of NULL function decl");
    }

    /* (filename):(line_num):(col_num):(function_name) */
    fprintf(typefile, "%s:%d:%d:%s ", 
            DECL_SOURCE_FILE(funct_decl), 
            DECL_SOURCE_LINE(funct_decl),
            DECL_SOURCE_COLUMN(funct_decl),
            IDENTIFIER_POINTER(DECL_NAME(funct_decl)));


    cdi_print_mangled_funct(typefile, funct_decl, loc);
    fputc('\n', typefile);
    CDI_EXIT();
}

void cdi_print_fp_info(FILE *typefile, tree fp_tree, location_t loc) {
    CDI_ENTER();
    if (!typefile || !cdi_function_ahead) {
        CDI_EXIT();
        return;
    }
    else if (!fp_tree) {
        cdi_warning_at(loc, "NULL fp_tree passed into cdi_print_fp_type_info");
        CDI_EXIT();
        return;
    }

    cdi_set_function_ahead(false);  
    
    /* deal with multi-layer indirection */
    while (fp_tree && TREE_CODE(fp_tree) == POINTER_TYPE) {
        fp_tree = TREE_TYPE(fp_tree);
    }
    tree funct_tree = fp_tree;

    if (funct_tree == NULL_TREE) {
        cdi_warning_at(loc, "removing indirections on fptor yields NULL tree");
        CDI_EXIT();
        return;
    }
    else if (TREE_CODE(funct_tree) != FUNCTION_TYPE) {
        CDI_EXIT();
        return;
    }

    cdi_print_loc(typefile, loc); 
    if (current_function_decl) {
        fprintf(typefile, ":%s ", IDENTIFIER_POINTER(
                    DECL_NAME(current_function_decl)));
    }
    else {
        cdi_warning_at(loc, "attempting to print function type signature "
                "between function definitions. Signatures should be recorded "
                "immediately after definitions");
        fprintf(typefile, ":? ");
    }

    cdi_print_mangled_funct(typefile, funct_tree, loc);
    fputc('\n', typefile);
    CDI_EXIT();
}

void cdi_print_mangled_funct(FILE *typefile, tree funct_tree, location_t loc) {
    CDI_ENTER();
    if (!typefile) { 
        CDI_EXIT();
        return;
    }
    else if (!funct_tree) {
        cdi_warning_at(loc, "attempted to mangle NULL_TREE. Skipping");
        CDI_EXIT();
        return;
    }
    else if (TREE_CODE(funct_tree) != FUNCTION_TYPE
            && TREE_CODE(funct_tree) != FUNCTION_DECL) {
        char msg[100];
        sprintf(msg, "attempted to mangle a non-function. "
                "Tree code: %.5d. Skipping", TREE_CODE(funct_tree));
        cdi_warning_at(loc, msg);
        CDI_EXIT();
        return;
    }

    tree funct_decl = NULL_TREE;
    if (TREE_CODE(funct_tree) == FUNCTION_DECL) {
        funct_decl = funct_tree;
        funct_tree = TREE_TYPE(funct_decl);
    }

    tree return_type = TREE_TYPE(funct_tree);

    fprintf(typefile, "_CDI");
    cdi_print_type(typefile, return_type, loc);
    fprintf(typefile, "_Z");

    if (funct_decl) {
        if (!TREE_PUBLIC(funct_decl)) {
            fputc('L', typefile);
        }
        const char *funct_name = IDENTIFIER_POINTER(DECL_NAME(funct_decl));
        fprintf(typefile, "%lu%s", strlen(funct_name), funct_name);
    }
    cdi_print_arg_types(typefile, funct_tree, loc);
    CDI_EXIT();
}

void cdi_print_type(FILE* stream, tree type, location_t loc) {
    CDI_ENTER();
    if (TREE_CODE(type) == FUNCTION_TYPE) {
        fputc('F', stream);
        cdi_print_type(stream, TREE_TYPE(type), loc);
        cdi_print_arg_types(stream, type, loc);
        fputc('E', stream);
        CDI_EXIT();
        return;
    }

    /* In this version, ignore cvr qualifiers. Note that we mustn't apply 
     * TYPE_MAIN_VARIANT() to an already unqualified type. */
    if (TYPE_QUALS_NO_ADDR_SPACE_NO_ATOMIC(type)) {
        type = TYPE_MAIN_VARIANT(type);
    }

    /* remove indirections */
    if (POINTER_TYPE_P(type)) {
        do {
            type = TREE_TYPE(type);
            fputc('P', stream);
        } while (type && POINTER_TYPE_P(type));

        if (type == NULL_TREE) {
            cdi_warning_at(loc, "argument is an impossible pointer type");
            fputc('?', stream);
            CDI_EXIT();
            return;
        }
    }

    /* for a function pointer argument type we need to recursively print the
     * function type info. This can't infinitely recurse because types can't
     * be recursively defined in C
     */
    if (TREE_CODE(type) == FUNCTION_TYPE) {
        cdi_print_type(stream, type, loc);
        CDI_EXIT();
        return;
    }
    else if (TREE_CODE(type) == ARRAY_TYPE) {
        cdi_print_type(stream, TYPE_POINTER_TO(TREE_TYPE(type)), loc);
        CDI_EXIT();
        return;
    }
    else if (RECORD_OR_UNION_TYPE_P(type) || TREE_CODE(type) == ENUMERAL_TYPE) {
        tree ident_node = TYPE_IDENTIFIER(type);
        if (ident_node) {
            const char *type_literal = IDENTIFIER_POINTER(ident_node);
            fprintf(stream, "%lu%s", strlen(type_literal), type_literal);
        }
        else {
            cdi_warning_at(loc, "unknown struct, union, or enumeral type");
            fprintf(stream, "?");
        }
    }
    else { 
        cdi_print_builtin_type(stream, type, loc);
    }
    CDI_EXIT();
}

/*
 * Return true iff the current token is treated as a function
 *
 * How it works: if the next non-close-parenthesis token is an open-parenthesis
 * token then the current token is treated as a function
 *
 * It might be tempting to peek n tokens ahead using the peek and consume
 * functions. It's a trap. Even though the token buffer has four slots, the 
 * parser can only really handle two tokens at a time. Don't try saving the parser
 * state and restoring after looking n tokens ahead. The lexing mechanism is 
 * somehow tied to the cpp parser and so you'd have to modify that too. In the end,
 * it's best to go to the source file and directly check the next characters
 */
bool cdi_is_function_ahead(c_parser *parser) {
    CDI_ENTER();
    location_t parser_loc = c_parser_peek_token(parser)->location;
    expanded_location parser_loc_info = expand_location(parser_loc);
    const char *filename = NULL;
    if (parser_loc_info.file) {
        filename = parser_loc_info.file;
    }
    else {
        filename = "?";
    }
    fprintf(stderr, "parser location: (%s, %d, %d)\n", 
            filename, parser_loc_info.line, parser_loc_info.column);

    enum cpp_ttype ahead1_type = c_parser_peek_token(parser)->type;
    enum cpp_ttype ahead2_type = c_parser_peek_2nd_token(parser)->type;

    if (ahead1_type == CPP_OPEN_PAREN ||
            (ahead1_type == CPP_CLOSE_PAREN && ahead2_type == CPP_OPEN_PAREN)) {
        CDI_EXIT();
        return true;
    }
    else if (ahead1_type == CPP_CLOSE_PAREN
            && ahead2_type == CPP_CLOSE_PAREN) {
        location_t close_paren2_loc = c_parser_peek_2nd_token(parser)->location;
        expanded_location loc_info = expand_location(close_paren2_loc);

        if (!loc_info.file) {
            cdi_warning_at(UNKNOWN_LOCATION, "couldn't find source file the parser is parsing."
                    " Ignoring this potential function pointer");
            CDI_EXIT();
            return false;
        }

        FILE *src = fopen(loc_info.file, "r");
        if (!src) {
            char msg[200];
            sprintf(msg, "couldn't open %.100s for reading. ignoring possible"
                    "function pointer", loc_info.file);
            cdi_warning_at(UNKNOWN_LOCATION, msg);
            CDI_EXIT();
            return false;
        }


        /* skip to the line with the close paren */
        int i = 0;
        while (fgetc(src) == '\n') {
            i++;
        }
        fseek(src, -1, SEEK_CUR);

        while (i < loc_info.line - 1) {
            fscanf(src, "%*[^\n]");
            while (fgetc(src) == '\n') {
                i++;
            }
            fseek(src, -1, SEEK_CUR);
        }

        /* skip to after the closer paren */
        fseek(src, loc_info.column, SEEK_CUR);

        char c = fgetc(src);
        while (c == ')' || c == ' ' || c == '\n') {
            c = fgetc(src);
        }

        fclose(src);
        CDI_EXIT();
        return c == '(';
    }
    else {
        CDI_EXIT();
        return false;
    }
}

static const char * const FTYPE_EXT = ".ftypes";
static const char * const FPTYPE_EXT = ".fptypes";

static FILE *cdi_ftype_file_ptr = NULL;
static FILE *cdi_fptype_file_ptr = NULL;

static char *cdi_fptype_filename = NULL;
static char *cdi_ftype_filename = NULL;

static Node *ftype_fnames_head = NULL;
static Node *fptype_fnames_head = NULL;

static FILE *cdi_get_typefile(Node **fnames_head,
    FILE **typefile_ptr, char **curr_typefile_name, const char *extension);

FILE *cdi_ftype_file() {
    return cdi_get_typefile(&ftype_fnames_head,
            &cdi_ftype_file_ptr, &cdi_ftype_filename, FTYPE_EXT);
}

FILE *cdi_fptype_file() {
    return cdi_get_typefile(&fptype_fnames_head,
            &cdi_fptype_file_ptr, &cdi_fptype_filename, FPTYPE_EXT);
}

static bool file_exists(const char* filename);

static FILE *cdi_get_typefile(Node **fnames_head,
    FILE **typefile_ptr, char **curr_typefile_name, const char *extension) {
    CDI_ENTER();

    char *old_typefile_name = *curr_typefile_name;

    // Construct the new typefile filename (e.g. main.c.ftypes)
    gcc_assert(strlen(LOCATION_FILE(input_location)) > 0);
    int new_typefile_len = strlen(LOCATION_FILE(input_location)) + strlen(extension);

    // +1 for the null byte terminating the c-string
    char *new_typefile_name = (char*)xmalloc(new_typefile_len + 1);
    strcpy(new_typefile_name, LOCATION_FILE(input_location));
    strcpy(new_typefile_name + strlen(LOCATION_FILE(input_location)), extension);

    fprintf(stderr, "typefile requested: %s\n", new_typefile_name);

    Node *node = get_node(*fnames_head, LOCATION_FILE(input_location));
    if (node) {
        fprintf(stderr, "'%s' node '%s' already in linked list\n", 
                extension, node->filename);
    }
    else {
        char *new_fname = (char*)xmalloc(strlen(LOCATION_FILE(input_location)) + 1);
        strcpy(new_fname, LOCATION_FILE(input_location));
        *fnames_head = add_node(*fnames_head, new_fname);
    }
    print_list(stderr, *fnames_head);
    

    // check if we have the same filename as last time
    if (old_typefile_name && !strcmp(old_typefile_name, new_typefile_name)) {
        free(new_typefile_name);
        new_typefile_name = NULL;
        CDI_EXIT();
        return *typefile_ptr;
    }
    else if (*typefile_ptr) {
        fclose(*typefile_ptr);
        free(old_typefile_name);

        old_typefile_name = NULL;
        *typefile_ptr = NULL;
        *curr_typefile_name = NULL;
    }

    FILE *new_typefile = fopen(new_typefile_name, "w");
    if (!new_typefile) {
        const char *msg_format = "cannot open '%s' for printing '%s' information";

        // this will be a little too large but a couple extra chars doesn't hurt
        char *msg = (char*)xmalloc(strlen(msg_format)
                + new_typefile_len + strlen(extension) + 1);
        if (sprintf(msg, msg_format, new_typefile_name, extension) < 0) {
            cdi_warning_at(UNKNOWN_LOCATION, "cannot open ftypes/fptypes file");
        }
        else {
            cdi_warning_at(UNKNOWN_LOCATION, msg);
        }

        free(msg);
        free(new_typefile_name);
        msg = NULL;
        new_typefile_name = NULL;
        CDI_EXIT();
        return NULL;
    }
   
    fprintf(stderr, "new typefile successfully opened\n");
    *curr_typefile_name = new_typefile_name;
    CDI_EXIT();
    return *typefile_ptr = new_typefile;
}

void cdi_print_arg_types(FILE *typefile, tree funct_tree, location_t loc) {
    CDI_ENTER();
    function_args_iterator iter;
    function_args_iter_init (&iter, funct_tree);
    tree arg_type = function_args_iter_cond (&iter);

    if (arg_type == NULL_TREE || arg_type == void_list_node) { 
        fputc('v', typefile);
        CDI_EXIT();
        return;
    }

    do {
        cdi_print_type(typefile, arg_type, loc);

        function_args_iter_next (&iter);
        arg_type = function_args_iter_cond (&iter);
    } while (arg_type && arg_type != void_list_node
            && TREE_CODE(arg_type) != VOID_TYPE);
}

/* Taken from the C++ implementation */
static const char
integer_type_codes[itk_none] =
{
    'c',  /* itk_char */
    'a',  /* itk_signed_char */
    'h',  /* itk_unsigned_char */
    's',  /* itk_short */
    't',  /* itk_unsigned_short */
    'i',  /* itk_int */
    'j',  /* itk_unsigned_int */
    'l',  /* itk_long */
    'm',  /* itk_unsigned_long */
    'x',  /* itk_long_long */
    'y',  /* itk_unsigned_long_long */
    /* __intN types are handled separately */
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'
};

/* Taken from the C++ implementation */
void
cdi_print_builtin_type(FILE *stream, tree type, location_t loc)
{
    CDI_ENTER();
    if (TYPE_CANONICAL (type))
        type = TYPE_CANONICAL (type);
    switch (TREE_CODE (type))
    {
        case VOID_TYPE:
            fputc ('v', stream);
            break;
        case BOOLEAN_TYPE:
            fputc ('b', stream);
            break;
        case INTEGER_TYPE:
            {
                size_t itk;
                /* Assume TYPE is one of the shared integer type nodes.  Find
                 *              it in the array of these nodes.  */
iagain:
                for (itk = 0; itk < itk_none; ++itk)
                    if (integer_types[itk] != NULL_TREE
                            && integer_type_codes[itk] != '\0'
                            && type == integer_types[itk])
                    {
                        /* Print the corresponding single-letter code.  */
                        fputc (integer_type_codes[itk], stream);
                        break;
                    }
                if (itk == itk_none)
                {
                    tree t = c_common_type_for_mode (TYPE_MODE (type),
                            TYPE_UNSIGNED (type));
                    if (type != t)
                    {
                        type = t;
                        goto iagain;
                    }
                    if (TYPE_PRECISION (type) == 128)
                        fputc ((TYPE_UNSIGNED (type) ? 'o' : 'n'), stream);
                    else
                    {
                        /* Allow for cases where TYPE is not one of the shared
                         * integer type nodes and write a "vendor extended builtin
                         * type" with a name the form intN or uintN, respectively.
                         * Situations like this can happen if you have an
                         * __attribute__((__mode__(__SI__))) type and use exotic
                         * switches like '-mint8' on AVR.  Of course, this is
                         * undefined by the C++ ABI (and '-mint8' is not even
                         * Standard C conforming), but when using such special
                         * options you're pretty much in nowhere land anyway.  */
                        const char *prefix;
                        char prec[11];        /* up to ten digits for an unsigned */
                        prefix = TYPE_UNSIGNED (type) ? "uint" : "int";
                        sprintf (prec, "%u", (unsigned) TYPE_PRECISION (type));
                        fputc ('u', stream);        /* "vendor extended builtin type" */
                        fprintf (stream, "%d", strlen (prefix) + strlen (prec));
                        fprintf(stream, prefix);
                        fprintf(stream, prec);
                    }
                }
            }
            break;
        case REAL_TYPE:
            if (type == float_type_node)
                fputc ('f', stream);
            else if (type == double_type_node)
                fputc ('d', stream);
            else if (type == long_double_type_node)
                fputc ('e', stream);
            else if (type == dfloat32_type_node)
                fprintf(stream, "Df");
            else if (type == dfloat64_type_node)
                fprintf(stream, "Dd");
            else if (type == dfloat128_type_node)
                fprintf(stream, "De");
            else if (TYPE_IDENTIFIER(type)) {
                const char *type_literal = 
                    IDENTIFIER_POINTER(TYPE_IDENTIFIER(type));
                if (!strcmp(type_literal, "__float128")) {
                    fputc('g', stream);
                    CDI_EXIT();
                    return;
                }

                const char *filename = NULL;
                int line_num = -1;
                int col_num = -1;
                if (DECL_P(TYPE_NAME(type))) {
                    expanded_location typedecl_loc = 
                        expand_location(DECL_SOURCE_LOCATION(TYPE_NAME(type)));
                    filename = typedecl_loc.file;
                    line_num = typedecl_loc.line;
                    col_num  = typedecl_loc.column;
                }

                char msg[250];
                sprintf(msg, "unknown \"builtin\" real type: '%.50s'. printing "
                        "type as if it were an identifier. type can be found "
                        " at %.50s:%d:%d", type_literal,
                        (filename ? filename : "?"), line_num, col_num);

                cdi_warning_at(loc, msg);

                fprintf(stream, "%lu%s", strlen(type_literal), type_literal);
            }
            else {
                const char *filename = NULL;
                int line_num = -1;
                int col_num = -1;
                if (DECL_P(TYPE_NAME(type))) {
                    expanded_location typedecl_loc = 
                        expand_location(DECL_SOURCE_LOCATION(TYPE_NAME(type)));
                    filename = typedecl_loc.file;
                    line_num = typedecl_loc.line;
                    col_num  = typedecl_loc.column;
                }
                char msg[200];
                sprintf(msg, "printing unknown \"builtin\" real type as 'R'. "
                        "type found at %.50s:%d:%d", 
                        (filename ? filename : "?"), line_num, col_num);

                cdi_warning_at(loc, msg);
                fputc('R', stream);
            }
                
            break;
        case FIXED_POINT_TYPE:
            fprintf(stream, "DF");
            if (GET_MODE_IBIT (TYPE_MODE (type)) > 0)
                fprintf(stream, "%d", (GET_MODE_IBIT (TYPE_MODE (type))));
            if (type == fract_type_node
                    || type == sat_fract_type_node
                    || type == accum_type_node
                    || type == sat_accum_type_node)
                fputc ('i', stream);
            else if (type == unsigned_fract_type_node
                    || type == sat_unsigned_fract_type_node
                    || type == unsigned_accum_type_node
                    || type == sat_unsigned_accum_type_node)
                fputc ('j', stream);
            else if (type == short_fract_type_node
                    || type == sat_short_fract_type_node
                    || type == short_accum_type_node
                    || type == sat_short_accum_type_node)
                fputc ('s', stream);
            else if (type == unsigned_short_fract_type_node
                    || type == sat_unsigned_short_fract_type_node
                    || type == unsigned_short_accum_type_node
                    || type == sat_unsigned_short_accum_type_node)
                fputc ('t', stream);
            else if (type == long_fract_type_node
                    || type == sat_long_fract_type_node
                    || type == long_accum_type_node
                    || type == sat_long_accum_type_node)
                fputc ('l', stream);
            else if (type == unsigned_long_fract_type_node
                    || type == sat_unsigned_long_fract_type_node
                    || type == unsigned_long_accum_type_node
                    || type == sat_unsigned_long_accum_type_node)
                fputc ('m', stream);
            else if (type == long_long_fract_type_node
                    || type == sat_long_long_fract_type_node
                    || type == long_long_accum_type_node
                    || type == sat_long_long_accum_type_node)
                fputc ('x', stream);
            else if (type == unsigned_long_long_fract_type_node
                    || type == sat_unsigned_long_long_fract_type_node
                    || type == unsigned_long_long_accum_type_node
                    || type == sat_unsigned_long_long_accum_type_node)
                fputc ('y', stream);
            else
                sorry ("mangling unknown fixed point type");
            fprintf(stream, "%d", (GET_MODE_FBIT (TYPE_MODE (type))));
            if (TYPE_SATURATING (type))
                fputc ('s', stream);
            else
                fputc ('n', stream);
            break;
        default:
            fputc('?', stream);
            cdi_warning_at(loc, "printing unknown tree type");
            fprintf(stderr, "unknown tree code: %d\n", TREE_CODE(type));
    }
    CDI_EXIT();
}

static bool file_exists(const char *filename) {
    return access(filename, F_OK) != -1;
       
    /*
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
    }
    return file != NULL;
    */
}

