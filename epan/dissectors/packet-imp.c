/* packet-imp.c
 * Routines for Apache Cassandra Internode Messaging Protocol dissection
 * Copyright 2021, Matt Fleming <matt@codeblueprint.co.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * IMP V3 reference: https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec
 * IMP V4 reference: https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec
 */

#include <config.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-imp.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-imp.h"
#endif

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_imp(void);
void proto_register_imp(void);

/* Initialize the protocol and registered fields */
static int proto_imp = -1;
static int hf_imp_sample_field = -1;
static int hf_imp_message_id = -1;
static int hf_imp_timestamp = -1;
static int hf_imp_verb  = -1;
static int hf_imp_flags  = -1;
static int hf_imp_params  = -1;
static int hf_imp_payload_size  = -1;
static expert_field ei_imp_expert = EI_INIT;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define imp_TCP_PORT 7000
static guint tcp_port_pref = imp_TCP_PORT;

/* Initialize the subtree pointers */
static gint ett_imp = -1;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define imp_MIN_LENGTH 8

enum verbs {
    MUTATION_RSP = 60,
    MUTATION_REQ = 0,
    HINT_RSP = 61,
    HINT_REQ = 1,
    READ_REPAIR_RSP = 62,
    READ_REPAIR_REQ = 2,
    BATCH_STORE_RSP = 65,
    BATCH_STORE_REQ = 5,
    BATCH_REMOVE_RSP = 66,
    BATCH_REMOVE_REQ = 6,

    PAXOS_PREPARE_RSP = 93,
    PAXOS_PREPARE_REQ = 33,
    PAXOS_PROPOSE_RSP = 94,
    PAXOS_PROPOSE_REQ = 34,
    PAXOS_COMMIT_RSP = 95,
    PAXOS_COMMIT_REQ = 35,

    TRUNCATE_RSP = 79,
    TRUNCATE_REQ = 19,

    COUNTER_MUTATION_RSP = 84,
    COUNTER_MUTATION_REQ = 24,

    READ_RSP = 63,
    READ_REQ = 3,
    RANGE_RSP = 69,
    RANGE_REQ = 9,
    MULTI_RANGE_RSP = 67,
    MULTI_RANGE_REQ = 7,

    GOSSIP_DIGEST_SYN = 14,
    GOSSIP_DIGEST_ACK = 15,
    GOSSIP_DIGEST_ACK2 = 16,
    GOSSIP_SHUTDOWN = 29,

    ECHO_RSP = 91,
    ECHO_REQ = 31,
    PING_RSP = 97,
    PING_REQ = 37,

    SCHEMA_PUSH_RSP = 98,
    SCHEMA_PUSH_REQ = 18,
    SCHEMA_PULL_RSP = 88,
    SCHEMA_PULL_REQ = 28,
    SCHEMA_VERSION_RSP = 80,
    SCHEMA_VERSION_REQ = 20,

    REPAIR_RSP = 100,
    VALIDATION_RSP = 102,
    VALIDATION_REQ = 101,
    SYNC_RSP = 104,
    SYNC_REQ = 103,
    PREPARE_MSG = 105,
    SNAPSHOT_MSG = 106,
    CLEANUP_MSG = 107,
    PREPARE_CONSISTENT_RSP = 109,
    PREPARE_CONSISTENT_REQ = 108,
    FINALIZE_PROPOSE_MSG = 110,
    FINALIZE_PROMISE_MSG = 111,
    FINALIZE_COMMIT_MSG = 112,
    FAILED_SESSION_MSG = 113,
    STATUS_RSP = 115,
    STATUS_REQ = 114,

    REPLICATION_DONE_RSP = 82,
    REPLICATION_DONE_REQ = 22,
    SNAPSHOT_RSP = 87,
    SNAPSHOT_REQ = 27,

    // generic failure response,
    FAILURE_RSP = 99,

    // Deprecated,
    REQUEST_RSP = 4,
    // Deprecated,
    INTERNAL_RSP = 23,

    // largest used ID: 116
};

static const val64_string verb_id_names[] = {
    {MUTATION_RSP, "MUTATION_RSP"},
    {MUTATION_REQ, "MUTATION_REQ"},
    {HINT_RSP, "HINT_RSP"},
    {HINT_REQ, "HINT_REQ"},
    {READ_REPAIR_RSP, "READ_REPAIR_RSP"},
    {READ_REPAIR_REQ, "READ_REPAIR_REQ"},
    {BATCH_STORE_RSP, "BATCH_STORE_RSP"},
    {BATCH_STORE_REQ, "BATCH_STORE_REQ"},
    {BATCH_REMOVE_RSP, "BATCH_REMOVE_RSP"},
    {BATCH_REMOVE_REQ, "BATCH_REMOVE_REQ"},

    {PAXOS_PREPARE_RSP, "PAXOS_PREPARE_RSP"},
    {PAXOS_PREPARE_REQ, "PAXOS_PREPARE_REQ"},
    {PAXOS_PROPOSE_RSP, "PAXOS_PROPOSE_RSP"},
    {PAXOS_PROPOSE_REQ, "PAXOS_PROPOSE_REQ"},
    {PAXOS_COMMIT_RSP, "PAXOS_COMMIT_RSP"},
    {PAXOS_COMMIT_REQ, "PAXOS_COMMIT_REQ"},

    {TRUNCATE_RSP, "TRUNCATE_RSP"},
    {TRUNCATE_REQ, "TRUNCATE_REQ"},

    {COUNTER_MUTATION_RSP, "COUNTER_MUTATION_RSP"},
    {COUNTER_MUTATION_REQ, "COUNTER_MUTATION_REQ"},

    {READ_RSP, "READ_RSP"},
    {READ_REQ, "READ_REQ"},
    {RANGE_RSP, "RANGE_RSP"},
    {RANGE_REQ, "RANGE_REQ"},
    {MULTI_RANGE_RSP, "MULTI_RANGE_RSP"},
    {MULTI_RANGE_REQ, "MULTI_RANGE_REQ"},

    {GOSSIP_DIGEST_SYN, "GOSSIP_DIGEST_SYN"},
    {GOSSIP_DIGEST_ACK, "GOSSIP_DIGEST_ACK"},
    {GOSSIP_DIGEST_ACK2, "GOSSIP_DIGEST_ACK2"},
    {GOSSIP_SHUTDOWN, "GOSSIP_SHUTDOWN"},

    {ECHO_RSP, "ECHO_RSP"},
    {ECHO_REQ, "ECHO_REQ"},
    {PING_RSP, "PING_RSP"},
    {PING_REQ, "PING_REQ"},

    {SCHEMA_PUSH_RSP, "SCHEMA_PUSH_RSP"},
    {SCHEMA_PUSH_REQ, "SCHEMA_PUSH_REQ"},
    {SCHEMA_PULL_RSP, "SCHEMA_PULL_RSP"},
    {SCHEMA_PULL_REQ, "SCHEMA_PULL_REQ"},
    {SCHEMA_VERSION_RSP, "SCHEMA_VERSION_RSP"},
    {SCHEMA_VERSION_REQ, "SCHEMA_VERSION_REQ"},

    {REPAIR_RSP, "REPAIR_RSP"},
    {VALIDATION_RSP, "VALIDATION_RSP"},
    {VALIDATION_REQ, "VALIDATION_REQ"},
    {SYNC_RSP, "SYNC_RSP"},
    {SYNC_REQ, "SYNC_REQ"},
    {PREPARE_MSG, "PREPARE_MSG"},
    {SNAPSHOT_MSG, "SNAPSHOT_MSG"},
    {CLEANUP_MSG, "CLEANUP_MSG"},
    {PREPARE_CONSISTENT_RSP, "PREPARE_CONSISTENT_RSP"},
    {PREPARE_CONSISTENT_REQ, "PREPARE_CONSISTENT_REQ"},
    {FINALIZE_PROPOSE_MSG, "FINALIZE_PROPOSE_MSG"},
    {FINALIZE_PROMISE_MSG, "FINALIZE_PROMISE_MSG"},
    {FINALIZE_COMMIT_MSG, "FINALIZE_COMMIT_MSG"},
    {FAILED_SESSION_MSG, "FAILED_SESSION_MSG"},
    {STATUS_RSP, "STATUS_RSP"},
    {STATUS_REQ, "STATUS_REQ"},

    {REPLICATION_DONE_RSP, "REPLICATION_DONE_RSP"},
    {REPLICATION_DONE_REQ, "REPLICATION_DONE_REQ"},
    {SNAPSHOT_RSP, "SNAPSHOT_RSP"},
    {SNAPSHOT_REQ, "SNAPSHOT_REQ"},

    // generic failure response,
    {FAILURE_RSP, "FAILURE_RSP"},

    // Deprecated,
    {REQUEST_RSP, "REQUEST_RSP"},
    // Deprecated,
    {INTERNAL_RSP, "INTERNAL_RSP"},

    {0, NULL}
};

static gint64 read_unsigned_vint(tvbuff_t *tvb, guint offset, guint *len)
{
    gint8 first_byte = tvb_get_gint8(tvb, offset);
    int num_bytes = 0;
    gint64 ret = 0;
    int i;

    *len = 1;

    if (first_byte >= 0)
        return first_byte;

    num_bytes = __builtin_clz(~first_byte) - 24;
    ret = first_byte & (0xff >> num_bytes);

    for (i = 0; i < num_bytes; i++) {
        gint8 b = tvb_get_gint8(tvb, offset + *len);
        ret <<= 8;
        ret |= b & 0xff;
        *len += 1;
    }

    return ret;
}

static void parse_gossip_digest_ack2(tvbuff_t *tvb, guint *offset)
{
    gint32 state_map_size = tvb_get_gint32(tvb, *offset, ENC_NA);
    *offset += 4;
}

/* Code to actually dissect the packets */
static int
dissect_imp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *imp_tree;
    /* Other misc. local variables. */

    /*
     * Not sure why this offset is required.
     */
    guint       offset = 6;
    guint       len = 0;

    /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */

    if (tvb_reported_length(tvb) < imp_MIN_LENGTH)
        return 0;

    /* Check that there's enough data present to run the heuristics. If there
     * isn't, reject the packet; it will probably be dissected as data and if
     * the user wants it dissected despite it being short they can use the
     * "Decode-As" functionality. If your heuristic needs to look very deep into
     * the packet you may not want to require *all* data to be present, but you
     * should ensure that the heuristic does not access beyond the captured
     * length of the packet regardless. */
    if (tvb_captured_length(tvb) < 1)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    if ( 0 )
        return 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'imp',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of imp */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "imp");

#if 0
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    col_set_str(pinfo->cinfo, COL_INFO, "");

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_imp, tvb, 0, -1, ENC_NA);

    imp_tree = proto_item_add_subtree(ti, ett_imp);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    gint64 id = read_unsigned_vint(tvb, offset, &len);
    proto_tree_add_uint(imp_tree, hf_imp_message_id, tvb, offset, len, id);
    offset += len;

    gint32 timestamp = tvb_get_gint32(tvb, offset, ENC_NA);
    proto_tree_add_uint(imp_tree, hf_imp_timestamp, tvb, offset, 4, timestamp);
    offset += 4;

    gint64 expiration = read_unsigned_vint(tvb, offset, &len);
    offset += len;
    /* Ignore expiration field */
    len = expiration;

    gint64 verb = read_unsigned_vint(tvb, offset, &len);
    proto_tree_add_uint(imp_tree, hf_imp_verb, tvb, offset, len, verb);
    offset += len;

    gint64 flags = read_unsigned_vint(tvb, offset, &len);
    proto_tree_add_uint(imp_tree, hf_imp_flags, tvb, offset, len, flags);
    offset += len;

    col_append_fstr(pinfo->cinfo, COL_INFO, "Verb=%s", val64_to_str(verb, verb_id_names, "Unknown (0x%02x)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Timestamp=%u", timestamp);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", MsgId=%ld", id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Flags=0x%08lx", flags);

    gint64 num_params = read_unsigned_vint(tvb, offset, &len);
    proto_tree_add_uint(imp_tree, hf_imp_params, tvb, offset, len, num_params);
    offset += len;

    /* TODO: handle param */

    gint64 payload_size = read_unsigned_vint(tvb, offset, &len);
    proto_tree_add_uint(imp_tree, hf_imp_payload_size, tvb, offset, len, payload_size);
    offset += len;

    /*
     * Decode payloads.
     */
    switch (verb) {
        case GOSSIP_DIGEST_ACK2:
            parse_gossip_digest_ack2(tvb, offset);
            break;
        default:
            break;
    }
    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_imp(void)
{
    module_t        *imp_module;
    expert_module_t *expert_imp;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_imp_sample_field,
          { "Sample Field", "imp.sample_field",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_imp_message_id,
          { "Message ID", "imp.message_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_imp_verb,
          { "Verb", "imp.verb",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_imp_flags,
          { "Flags", "imp.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_imp_params,
          { "Params", "imp.params",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_imp_payload_size,
          { "Payload size", "imp.payload_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_imp_timestamp,
          { "Timestamp", "imp.timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        }
     };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_imp
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_imp_expert,
          { "imp.expert", PI_PROTOCOL, PI_ERROR,
            "EXPERTDESCR", EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_imp = proto_register_protocol("Cassandra Internode Messaging Protocol",
            "IMP", "imp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_imp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_imp = expert_register_protocol(proto_imp);
    expert_register_field_array(expert_imp, ei, array_length(ei));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_imp in the following.
     */
    imp_module = prefs_register_protocol(proto_imp,
            proto_reg_handoff_imp);

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><IMP>
     * preferences node.
     */
#if 0
    imp_module = prefs_register_protocol_subtree("",
            proto_imp, proto_reg_handoff_imp);
#endif

    /* Register a simple example preference */
    prefs_register_bool_preference(imp_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &pref_hex);

    /* Register an example port preference */
    prefs_register_uint_preference(imp_module, "tcp.port", "imp TCP Port",
            " imp TCP port if other than the default",
            10, &tcp_port_pref);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_imp(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t imp_handle;
    static int current_port;

    if (!initialized) {
        /* Use create_dissector_handle() to indicate that
         * dissect_imp() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to Cassandra Internode Messaging Protocol).
         */
        imp_handle = create_dissector_handle(dissect_imp,
                proto_imp);
        initialized = TRUE;

    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the imp_handle and the value the preference had at the time
         * you registered.  The imp_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        dissector_delete_uint("tcp.port", current_port, imp_handle);
    }

    current_port = tcp_port_pref;

    dissector_add_uint("tcp.port", current_port, imp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
