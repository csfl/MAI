#pragma once

#include <mol/common.hpp>

namespace mol
{
class block_store;
class stat;

class shared_ptr_block_hash
{
public:
	size_t operator() (std::shared_ptr<mol::block> const &) const;
	bool operator() (std::shared_ptr<mol::block> const &, std::shared_ptr<mol::block> const &) const;
};
using tally_t = std::map<mol::uint128_t, std::shared_ptr<mol::block>, std::greater<mol::uint128_t>>;
class ledger
{
public:
	ledger (mol::block_store &, mol::stat &, mol::block_hash const & = 0, mol::block_hash const & = 0);
	std::pair<mol::uint128_t, std::shared_ptr<mol::block>> winner (MDB_txn *, mol::votes const & votes_a);
	// Map of weight -> associated block, ordered greatest to least
	mol::tally_t tally (MDB_txn *, mol::votes const &);
	mol::account account (MDB_txn *, mol::block_hash const &);
	mol::uint128_t amount (MDB_txn *, mol::block_hash const &);
	mol::uint128_t balance (MDB_txn *, mol::block_hash const &);
	mol::uint128_t account_balance (MDB_txn *, mol::account const &);
	mol::uint128_t account_pending (MDB_txn *, mol::account const &);
	mol::uint128_t weight (MDB_txn *, mol::account const &);
	std::unique_ptr<mol::block> successor (MDB_txn *, mol::block_hash const &);
	std::unique_ptr<mol::block> forked_block (MDB_txn *, mol::block const &);
	mol::block_hash latest (MDB_txn *, mol::account const &);
	mol::block_hash latest_root (MDB_txn *, mol::account const &);
	mol::block_hash representative (MDB_txn *, mol::block_hash const &);
	mol::block_hash representative_calculated (MDB_txn *, mol::block_hash const &);
	bool block_exists (mol::block_hash const &);
	std::string block_text (char const *);
	std::string block_text (mol::block_hash const &);
	bool is_send (MDB_txn *, mol::state_block const &);
	mol::block_hash block_destination (MDB_txn *, mol::block const &);
	mol::block_hash block_source (MDB_txn *, mol::block const &);
	mol::process_return process (MDB_txn *, mol::block const &);
	void rollback (MDB_txn *, mol::block_hash const &);
	void change_latest (MDB_txn *, mol::account const &, mol::block_hash const &, mol::account const &, mol::uint128_union const &, uint64_t, bool = false);
	void checksum_update (MDB_txn *, mol::block_hash const &);
	mol::checksum checksum (MDB_txn *, mol::account const &, mol::account const &);
	void dump_account_chain (mol::account const &);
	bool state_block_parsing_enabled (MDB_txn *);
	bool state_block_generation_enabled (MDB_txn *);
	static mol::uint128_t const unit;
	mol::block_store & store;
	mol::stat & stats;
	std::unordered_map<mol::account, mol::uint128_t> bootstrap_weights;
	uint64_t bootstrap_weight_max_blocks;
	std::atomic<bool> check_bootstrap_weights;
	mol::block_hash state_block_parse_canary;
	mol::block_hash state_block_generate_canary;
};
};
