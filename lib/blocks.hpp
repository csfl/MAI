#pragma once

#include <mol/lib/numbers.hpp>

#include <assert.h>
#include <blake2/blake2.h>
#include <boost/property_tree/json_parser.hpp>
#include <streambuf>

namespace mol
{
std::string to_string_hex (uint64_t);
bool from_string_hex (std::string const &, uint64_t &);
// We operate on streams of uint8_t by convention
using stream = std::basic_streambuf<uint8_t>;
// Read a raw byte stream the size of `T' and fill value.
template <typename T>
bool read (mol::stream & stream_a, T & value)
{
	static_assert (std::is_pod<T>::value, "Can't stream read non-standard layout types");
	auto amount_read (stream_a.sgetn (reinterpret_cast<uint8_t *> (&value), sizeof (value)));
	return amount_read != sizeof (value);
}
template <typename T>
void write (mol::stream & stream_a, T const & value)
{
	static_assert (std::is_pod<T>::value, "Can't stream write non-standard layout types");
	auto amount_written (stream_a.sputn (reinterpret_cast<uint8_t const *> (&value), sizeof (value)));
	assert (amount_written == sizeof (value));
}
class block_visitor;
enum class block_type : uint8_t
{
	invalid = 0,
	not_a_block = 1,
	send = 2,
	receive = 3,
	open = 4,
	change = 5,
	state = 6
};
class block
{
public:
	// Return a digest of the hashables in this block.
	mol::block_hash hash () const;
	std::string to_json ();
	virtual void hash (blake2b_state &) const = 0;
	virtual uint64_t block_work () const = 0;
	virtual void block_work_set (uint64_t) = 0;
	// Previous block in account's chain, zero for open block
	virtual mol::block_hash previous () const = 0;
	// Source block for open/receive blocks, zero otherwise.
	virtual mol::block_hash source () const = 0;
	// Previous block or account number for open blocks
	virtual mol::block_hash root () const = 0;
	virtual mol::account representative () const = 0;
	virtual void serialize (mol::stream &) const = 0;
	virtual void serialize_json (std::string &) const = 0;
	virtual void visit (mol::block_visitor &) const = 0;
	virtual bool operator== (mol::block const &) const = 0;
	virtual mol::block_type type () const = 0;
	virtual mol::signature block_signature () const = 0;
	virtual void signature_set (mol::uint512_union const &) = 0;
	virtual ~block () = default;
	virtual bool valid_predecessor (mol::block const &) const = 0;
};
class send_hashables
{
public:
	send_hashables (mol::account const &, mol::block_hash const &, mol::amount const &);
	send_hashables (bool &, mol::stream &);
	send_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	mol::block_hash previous;
	mol::account destination;
	mol::amount balance;
};
class send_block : public mol::block
{
public:
	send_block (mol::block_hash const &, mol::account const &, mol::amount const &, mol::raw_key const &, mol::public_key const &, uint64_t);
	send_block (bool &, mol::stream &);
	send_block (bool &, boost::property_tree::ptree const &);
	virtual ~send_block () = default;
	using mol::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	mol::block_hash previous () const override;
	mol::block_hash source () const override;
	mol::block_hash root () const override;
	mol::account representative () const override;
	void serialize (mol::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (mol::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (mol::block_visitor &) const override;
	mol::block_type type () const override;
	mol::signature block_signature () const override;
	void signature_set (mol::uint512_union const &) override;
	bool operator== (mol::block const &) const override;
	bool operator== (mol::send_block const &) const;
	bool valid_predecessor (mol::block const &) const override;
	static size_t constexpr size = sizeof (mol::account) + sizeof (mol::block_hash) + sizeof (mol::amount) + sizeof (mol::signature) + sizeof (uint64_t);
	send_hashables hashables;
	mol::signature signature;
	uint64_t work;
};
class receive_hashables
{
public:
	receive_hashables (mol::block_hash const &, mol::block_hash const &);
	receive_hashables (bool &, mol::stream &);
	receive_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	mol::block_hash previous;
	mol::block_hash source;
};
class receive_block : public mol::block
{
public:
	receive_block (mol::block_hash const &, mol::block_hash const &, mol::raw_key const &, mol::public_key const &, uint64_t);
	receive_block (bool &, mol::stream &);
	receive_block (bool &, boost::property_tree::ptree const &);
	virtual ~receive_block () = default;
	using mol::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	mol::block_hash previous () const override;
	mol::block_hash source () const override;
	mol::block_hash root () const override;
	mol::account representative () const override;
	void serialize (mol::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (mol::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (mol::block_visitor &) const override;
	mol::block_type type () const override;
	mol::signature block_signature () const override;
	void signature_set (mol::uint512_union const &) override;
	bool operator== (mol::block const &) const override;
	bool operator== (mol::receive_block const &) const;
	bool valid_predecessor (mol::block const &) const override;
	static size_t constexpr size = sizeof (mol::block_hash) + sizeof (mol::block_hash) + sizeof (mol::signature) + sizeof (uint64_t);
	receive_hashables hashables;
	mol::signature signature;
	uint64_t work;
};
class open_hashables
{
public:
	open_hashables (mol::block_hash const &, mol::account const &, mol::account const &);
	open_hashables (bool &, mol::stream &);
	open_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	mol::block_hash source;
	mol::account representative;
	mol::account account;
};
class open_block : public mol::block
{
public:
	open_block (mol::block_hash const &, mol::account const &, mol::account const &, mol::raw_key const &, mol::public_key const &, uint64_t);
	open_block (mol::block_hash const &, mol::account const &, mol::account const &, std::nullptr_t);
	open_block (bool &, mol::stream &);
	open_block (bool &, boost::property_tree::ptree const &);
	virtual ~open_block () = default;
	using mol::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	mol::block_hash previous () const override;
	mol::block_hash source () const override;
	mol::block_hash root () const override;
	mol::account representative () const override;
	void serialize (mol::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (mol::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (mol::block_visitor &) const override;
	mol::block_type type () const override;
	mol::signature block_signature () const override;
	void signature_set (mol::uint512_union const &) override;
	bool operator== (mol::block const &) const override;
	bool operator== (mol::open_block const &) const;
	bool valid_predecessor (mol::block const &) const override;
	static size_t constexpr size = sizeof (mol::block_hash) + sizeof (mol::account) + sizeof (mol::account) + sizeof (mol::signature) + sizeof (uint64_t);
	mol::open_hashables hashables;
	mol::signature signature;
	uint64_t work;
};
class change_hashables
{
public:
	change_hashables (mol::block_hash const &, mol::account const &);
	change_hashables (bool &, mol::stream &);
	change_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	mol::block_hash previous;
	mol::account representative;
};
class change_block : public mol::block
{
public:
	change_block (mol::block_hash const &, mol::account const &, mol::raw_key const &, mol::public_key const &, uint64_t);
	change_block (bool &, mol::stream &);
	change_block (bool &, boost::property_tree::ptree const &);
	virtual ~change_block () = default;
	using mol::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	mol::block_hash previous () const override;
	mol::block_hash source () const override;
	mol::block_hash root () const override;
	mol::account representative () const override;
	void serialize (mol::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (mol::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (mol::block_visitor &) const override;
	mol::block_type type () const override;
	mol::signature block_signature () const override;
	void signature_set (mol::uint512_union const &) override;
	bool operator== (mol::block const &) const override;
	bool operator== (mol::change_block const &) const;
	bool valid_predecessor (mol::block const &) const override;
	static size_t constexpr size = sizeof (mol::block_hash) + sizeof (mol::account) + sizeof (mol::signature) + sizeof (uint64_t);
	mol::change_hashables hashables;
	mol::signature signature;
	uint64_t work;
};
class state_hashables
{
public:
	state_hashables (mol::account const &, mol::block_hash const &, mol::account const &, mol::amount const &, mol::uint256_union const &);
	state_hashables (bool &, mol::stream &);
	state_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	// Account# / public key that operates this account
	// Uses:
	// Bulk signature validation in advance of further ledger processing
	// Arranging uncomitted transactions by account
	mol::account account;
	// Previous transaction in this chain
	mol::block_hash previous;
	// Representative of this account
	mol::account representative;
	// Current balance of this account
	// Allows lookup of account balance simply by looking at the head block
	mol::amount balance;
	// Link field contains source block_hash if receiving, destination account if sending
	mol::uint256_union link;
};
class state_block : public mol::block
{
public:
	state_block (mol::account const &, mol::block_hash const &, mol::account const &, mol::amount const &, mol::uint256_union const &, mol::raw_key const &, mol::public_key const &, uint64_t);
	state_block (bool &, mol::stream &);
	state_block (bool &, boost::property_tree::ptree const &);
	virtual ~state_block () = default;
	using mol::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	mol::block_hash previous () const override;
	mol::block_hash source () const override;
	mol::block_hash root () const override;
	mol::account representative () const override;
	void serialize (mol::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (mol::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (mol::block_visitor &) const override;
	mol::block_type type () const override;
	mol::signature block_signature () const override;
	void signature_set (mol::uint512_union const &) override;
	bool operator== (mol::block const &) const override;
	bool operator== (mol::state_block const &) const;
	bool valid_predecessor (mol::block const &) const override;
	static size_t constexpr size = sizeof (mol::account) + sizeof (mol::block_hash) + sizeof (mol::account) + sizeof (mol::amount) + sizeof (mol::uint256_union) + sizeof (mol::signature) + sizeof (uint64_t);
	mol::state_hashables hashables;
	mol::signature signature;
	uint64_t work;
};
//added by sandy - s
class astate_hashables {
public:
	astate_hashables (mol::account const &, mol::block_hash const &, mol::account const &, mol::amount const &, mol::uint256_union const &, mol::asset const &, mol::account const &);
	astate_hashables (bool &, mol::stream &);
	astate_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	// Account# / public key that operates this account
	// Uses:
	// Bulk signature validation in advance of further ledger processing
	// Arranging uncomitted transactions by account
	mol::account account;
	// Previous transaction in this chain
	mol::block_hash previous;
	// Representative of this account
	mol::account representative;
	// Current balance of this account
	// Allows lookup of account balance simply by looking at the head block
	mol::amount balance;
	// Link field contains source block_hash if receiving, destination account if sending
	mol::uint256_union link;

	mol::asset asset;
	mol::account genesis_account;

};
class astate_block : public mol::block {
public:
	astate_block (mol::account const &, mol::block_hash const &, mol::account const &, mol::amount const &, mol::uint256_union const &, mol::asset const &, mol::account const &, char const *, mol::raw_key const &, mol::public_key const &, uint64_t);
	astate_block (bool &, mol::stream &);
	astate_block (bool &, boost::property_tree::ptree const &);
	virtual ~astate_block () = default;
	using mol::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	mol::block_hash previous () const override;
	mol::block_hash source () const override;
	mol::block_hash root () const override;
	mol::account representative () const override;
	void serialize (mol::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (mol::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (mol::block_visitor &) const override;
	mol::block_type type () const override;
	mol::signature block_signature () const override;
	std::string block_identifier ();
	void signature_set (mol::uint512_union const &) override;
	bool operator== (mol::block const &) const override;
	bool operator== (mol::astate_block const &) const;
	bool valid_predecessor (mol::block const &) const override;
	static size_t constexpr size = sizeof (mol::account) + sizeof (mol::block_hash) + sizeof (mol::account) + sizeof (mol::amount) + sizeof (mol::uint256_union) + sizeof(mol::asset) + sizeof(mol::account) +
								   sizeof(char)*4 + sizeof (mol::signature) + sizeof (uint64_t);
	mol::astate_hashables hashables;

	mol::signature signature;
	uint64_t work;
	char identifier[4];
};
//added by sandy - e
class block_visitor
{
public:
	virtual void send_block (mol::send_block const &) = 0;
	virtual void receive_block (mol::receive_block const &) = 0;
	virtual void open_block (mol::open_block const &) = 0;
	virtual void change_block (mol::change_block const &) = 0;
	virtual void state_block (mol::state_block const &) = 0;
	virtual void astate_block (mol::astate_block const &) = 0;
	virtual ~block_visitor () = default;
};
std::unique_ptr<mol::block> deserialize_block (mol::stream &);
std::unique_ptr<mol::block> deserialize_block (mol::stream &, mol::block_type);
std::unique_ptr<mol::block> deserialize_block_json (boost::property_tree::ptree const &);
void serialize_block (mol::stream &, mol::block const &);
}
