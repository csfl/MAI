#include <mol/lib/blocks.hpp>

#include <boost/endian/conversion.hpp>

/** Compare blocks, first by type, then content. This is an optimization over dynamic_cast, which is very slow on some platforms. */
namespace
{
template <typename T>
bool blocks_equal (T const & first, mol::block const & second)
{
	static_assert (std::is_base_of<mol::block, T>::value, "Input parameter is not a block type");
	return (first.type () == second.type ()) && (static_cast<T const &> (second)) == first;
}
}

std::string mol::to_string_hex (uint64_t value_a)
{
	std::stringstream stream;
	stream << std::hex << std::noshowbase << std::setw (16) << std::setfill ('0');
	stream << value_a;
	return stream.str ();
}

bool mol::from_string_hex (std::string const & value_a, uint64_t & target_a)
{
	auto error (value_a.empty ());
	if (!error)
	{
		error = value_a.size () > 16;
		if (!error)
		{
			std::stringstream stream (value_a);
			stream << std::hex << std::noshowbase;
			try
			{
				uint64_t number_l;
				stream >> number_l;
				target_a = number_l;
				if (!stream.eof ())
				{
					error = true;
				}
			}
			catch (std::runtime_error &)
			{
				error = true;
			}
		}
	}
	return error;
}

std::string mol::block::to_json ()
{
	std::string result;
	serialize_json (result);
	return result;
}

mol::block_hash mol::block::hash () const
{
	mol::uint256_union result;
	blake2b_state hash_l;
	auto status (blake2b_init (&hash_l, sizeof (result.bytes)));
	assert (status == 0);
	hash (hash_l);
	status = blake2b_final (&hash_l, result.bytes.data (), sizeof (result.bytes));
	assert (status == 0);
	return result;
}

void mol::send_block::visit (mol::block_visitor & visitor_a) const
{
	visitor_a.send_block (*this);
}

void mol::send_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t mol::send_block::block_work () const
{
	return work;
}

void mol::send_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

mol::send_hashables::send_hashables (mol::block_hash const & previous_a, mol::account const & destination_a, mol::amount const & balance_a) :
previous (previous_a),
destination (destination_a),
balance (balance_a)
{
}

mol::send_hashables::send_hashables (bool & error_a, mol::stream & stream_a)
{
	error_a = mol::read (stream_a, previous.bytes);
	if (!error_a)
	{
		error_a = mol::read (stream_a, destination.bytes);
		if (!error_a)
		{
			error_a = mol::read (stream_a, balance.bytes);
		}
	}
}

mol::send_hashables::send_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto destination_l (tree_a.get<std::string> ("destination"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = destination.decode_account (destination_l);
			if (!error_a)
			{
				error_a = balance.decode_hex (balance_l);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void mol::send_hashables::hash (blake2b_state & hash_a) const
{
	auto status (blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes)));
	assert (status == 0);
	status = blake2b_update (&hash_a, destination.bytes.data (), sizeof (destination.bytes));
	assert (status == 0);
	status = blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	assert (status == 0);
}

void mol::send_block::serialize (mol::stream & stream_a) const
{
	write (stream_a, hashables.previous.bytes);
	write (stream_a, hashables.destination.bytes);
	write (stream_a, hashables.balance.bytes);
	write (stream_a, signature.bytes);
	write (stream_a, work);
}

void mol::send_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "send");
	std::string previous;
	hashables.previous.encode_hex (previous);
	tree.put ("previous", previous);
	tree.put ("destination", hashables.destination.to_account ());
	std::string balance;
	hashables.balance.encode_hex (balance);
	tree.put ("balance", balance);
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", mol::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool mol::send_block::deserialize (mol::stream & stream_a)
{
	auto error (false);
	error = read (stream_a, hashables.previous.bytes);
	if (!error)
	{
		error = read (stream_a, hashables.destination.bytes);
		if (!error)
		{
			error = read (stream_a, hashables.balance.bytes);
			if (!error)
			{
				error = read (stream_a, signature.bytes);
				if (!error)
				{
					error = read (stream_a, work);
				}
			}
		}
	}
	return error;
}

bool mol::send_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "send");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto destination_l (tree_a.get<std::string> ("destination"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.destination.decode_account (destination_l);
			if (!error)
			{
				error = hashables.balance.decode_hex (balance_l);
				if (!error)
				{
					error = mol::from_string_hex (work_l, work);
					if (!error)
					{
						error = signature.decode_hex (signature_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

mol::send_block::send_block (mol::block_hash const & previous_a, mol::account const & destination_a, mol::amount const & balance_a, mol::raw_key const & prv_a, mol::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, destination_a, balance_a),
signature (mol::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

mol::send_block::send_block (bool & error_a, mol::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = mol::read (stream_a, signature.bytes);
		if (!error_a)
		{
			error_a = mol::read (stream_a, work);
		}
	}
}

mol::send_block::send_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = signature.decode_hex (signature_l);
			if (!error_a)
			{
				error_a = mol::from_string_hex (work_l, work);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

bool mol::send_block::operator== (mol::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool mol::send_block::valid_predecessor (mol::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case mol::block_type::send:
		case mol::block_type::receive:
		case mol::block_type::open:
		case mol::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

mol::block_type mol::send_block::type () const
{
	return mol::block_type::send;
}

bool mol::send_block::operator== (mol::send_block const & other_a) const
{
	auto result (hashables.destination == other_a.hashables.destination && hashables.previous == other_a.hashables.previous && hashables.balance == other_a.hashables.balance && work == other_a.work && signature == other_a.signature);
	return result;
}

mol::block_hash mol::send_block::previous () const
{
	return hashables.previous;
}

mol::block_hash mol::send_block::source () const
{
	return 0;
}

mol::block_hash mol::send_block::root () const
{
	return hashables.previous;
}

mol::account mol::send_block::representative () const
{
	return 0;
}

mol::signature mol::send_block::block_signature () const
{
	return signature;
}

void mol::send_block::signature_set (mol::uint512_union const & signature_a)
{
	signature = signature_a;
}

mol::open_hashables::open_hashables (mol::block_hash const & source_a, mol::account const & representative_a, mol::account const & account_a) :
source (source_a),
representative (representative_a),
account (account_a)
{
}

mol::open_hashables::open_hashables (bool & error_a, mol::stream & stream_a)
{
	error_a = mol::read (stream_a, source.bytes);
	if (!error_a)
	{
		error_a = mol::read (stream_a, representative.bytes);
		if (!error_a)
		{
			error_a = mol::read (stream_a, account.bytes);
		}
	}
}

mol::open_hashables::open_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto source_l (tree_a.get<std::string> ("source"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto account_l (tree_a.get<std::string> ("account"));
		error_a = source.decode_hex (source_l);
		if (!error_a)
		{
			error_a = representative.decode_account (representative_l);
			if (!error_a)
			{
				error_a = account.decode_account (account_l);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void mol::open_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, source.bytes.data (), sizeof (source.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
}

mol::open_block::open_block (mol::block_hash const & source_a, mol::account const & representative_a, mol::account const & account_a, mol::raw_key const & prv_a, mol::public_key const & pub_a, uint64_t work_a) :
hashables (source_a, representative_a, account_a),
signature (mol::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
	assert (!representative_a.is_zero ());
}

mol::open_block::open_block (mol::block_hash const & source_a, mol::account const & representative_a, mol::account const & account_a, std::nullptr_t) :
hashables (source_a, representative_a, account_a),
work (0)
{
	signature.clear ();
}

mol::open_block::open_block (bool & error_a, mol::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = mol::read (stream_a, signature);
		if (!error_a)
		{
			error_a = mol::read (stream_a, work);
		}
	}
}

mol::open_block::open_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l (tree_a.get<std::string> ("work"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			error_a = mol::from_string_hex (work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex (signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void mol::open_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t mol::open_block::block_work () const
{
	return work;
}

void mol::open_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

mol::block_hash mol::open_block::previous () const
{
	mol::block_hash result (0);
	return result;
}

void mol::open_block::serialize (mol::stream & stream_a) const
{
	write (stream_a, hashables.source);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.account);
	write (stream_a, signature);
	write (stream_a, work);
}

void mol::open_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "open");
	tree.put ("source", hashables.source.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("account", hashables.account.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", mol::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool mol::open_block::deserialize (mol::stream & stream_a)
{
	auto error (read (stream_a, hashables.source));
	if (!error)
	{
		error = read (stream_a, hashables.representative);
		if (!error)
		{
			error = read (stream_a, hashables.account);
			if (!error)
			{
				error = read (stream_a, signature);
				if (!error)
				{
					error = read (stream_a, work);
				}
			}
		}
	}
	return error;
}

bool mol::open_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "open");
		auto source_l (tree_a.get<std::string> ("source"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto account_l (tree_a.get<std::string> ("account"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.source.decode_hex (source_l);
		if (!error)
		{
			error = hashables.representative.decode_hex (representative_l);
			if (!error)
			{
				error = hashables.account.decode_hex (account_l);
				if (!error)
				{
					error = mol::from_string_hex (work_l, work);
					if (!error)
					{
						error = signature.decode_hex (signature_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void mol::open_block::visit (mol::block_visitor & visitor_a) const
{
	visitor_a.open_block (*this);
}

mol::block_type mol::open_block::type () const
{
	return mol::block_type::open;
}

bool mol::open_block::operator== (mol::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool mol::open_block::operator== (mol::open_block const & other_a) const
{
	return hashables.source == other_a.hashables.source && hashables.representative == other_a.hashables.representative && hashables.account == other_a.hashables.account && work == other_a.work && signature == other_a.signature;
}

bool mol::open_block::valid_predecessor (mol::block const & block_a) const
{
	return false;
}

mol::block_hash mol::open_block::source () const
{
	return hashables.source;
}

mol::block_hash mol::open_block::root () const
{
	return hashables.account;
}

mol::account mol::open_block::representative () const
{
	return hashables.representative;
}

mol::signature mol::open_block::block_signature () const
{
	return signature;
}

void mol::open_block::signature_set (mol::uint512_union const & signature_a)
{
	signature = signature_a;
}

mol::change_hashables::change_hashables (mol::block_hash const & previous_a, mol::account const & representative_a) :
previous (previous_a),
representative (representative_a)
{
}

mol::change_hashables::change_hashables (bool & error_a, mol::stream & stream_a)
{
	error_a = mol::read (stream_a, previous);
	if (!error_a)
	{
		error_a = mol::read (stream_a, representative);
	}
}

mol::change_hashables::change_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = representative.decode_account (representative_l);
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void mol::change_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
}

mol::change_block::change_block (mol::block_hash const & previous_a, mol::account const & representative_a, mol::raw_key const & prv_a, mol::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, representative_a),
signature (mol::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

mol::change_block::change_block (bool & error_a, mol::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = mol::read (stream_a, signature);
		if (!error_a)
		{
			error_a = mol::read (stream_a, work);
		}
	}
}

mol::change_block::change_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l (tree_a.get<std::string> ("work"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			error_a = mol::from_string_hex (work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex (signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void mol::change_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t mol::change_block::block_work () const
{
	return work;
}

void mol::change_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

mol::block_hash mol::change_block::previous () const
{
	return hashables.previous;
}

void mol::change_block::serialize (mol::stream & stream_a) const
{
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, signature);
	write (stream_a, work);
}

void mol::change_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "change");
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("work", mol::to_string_hex (work));
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool mol::change_block::deserialize (mol::stream & stream_a)
{
	auto error (read (stream_a, hashables.previous));
	if (!error)
	{
		error = read (stream_a, hashables.representative);
		if (!error)
		{
			error = read (stream_a, signature);
			if (!error)
			{
				error = read (stream_a, work);
			}
		}
	}
	return error;
}

bool mol::change_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "change");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.representative.decode_hex (representative_l);
			if (!error)
			{
				error = mol::from_string_hex (work_l, work);
				if (!error)
				{
					error = signature.decode_hex (signature_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void mol::change_block::visit (mol::block_visitor & visitor_a) const
{
	visitor_a.change_block (*this);
}

mol::block_type mol::change_block::type () const
{
	return mol::block_type::change;
}

bool mol::change_block::operator== (mol::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool mol::change_block::operator== (mol::change_block const & other_a) const
{
	return hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && work == other_a.work && signature == other_a.signature;
}

bool mol::change_block::valid_predecessor (mol::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case mol::block_type::send:
		case mol::block_type::receive:
		case mol::block_type::open:
		case mol::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

mol::block_hash mol::change_block::source () const
{
	return 0;
}

mol::block_hash mol::change_block::root () const
{
	return hashables.previous;
}

mol::account mol::change_block::representative () const
{
	return hashables.representative;
}

mol::signature mol::change_block::block_signature () const
{
	return signature;
}

void mol::change_block::signature_set (mol::uint512_union const & signature_a)
{
	signature = signature_a;
}

mol::state_hashables::state_hashables (mol::account const & account_a, mol::block_hash const & previous_a, mol::account const & representative_a, mol::amount const & balance_a, mol::uint256_union const & link_a) :
account (account_a),
previous (previous_a),
representative (representative_a),
balance (balance_a),
link (link_a)
{
}

mol::state_hashables::state_hashables (bool & error_a, mol::stream & stream_a)
{
	error_a = mol::read (stream_a, account);
	if (!error_a)
	{
		error_a = mol::read (stream_a, previous);
		if (!error_a)
		{
			error_a = mol::read (stream_a, representative);
			if (!error_a)
			{
				error_a = mol::read (stream_a, balance);
				if (!error_a)
				{
					error_a = mol::read (stream_a, link);
				}
			}
		}
	}
}

mol::state_hashables::state_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		error_a = account.decode_account (account_l);
		if (!error_a)
		{
			error_a = previous.decode_hex (previous_l);
			if (!error_a)
			{
				error_a = representative.decode_account (representative_l);
				if (!error_a)
				{
					error_a = balance.decode_dec (balance_l);
					if (!error_a)
					{
						error_a = link.decode_account (link_l) && link.decode_hex (link_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void mol::state_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	blake2b_update (&hash_a, link.bytes.data (), sizeof (link.bytes));
}

mol::state_block::state_block (mol::account const & account_a, mol::block_hash const & previous_a, mol::account const & representative_a, mol::amount const & balance_a, mol::uint256_union const & link_a, mol::raw_key const & prv_a, mol::public_key const & pub_a, uint64_t work_a) :
hashables (account_a, previous_a, representative_a, balance_a, link_a),
signature (mol::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

mol::state_block::state_block (bool & error_a, mol::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = mol::read (stream_a, signature);
		if (!error_a)
		{
			error_a = mol::read (stream_a, work);
			boost::endian::big_to_native_inplace (work);
		}
	}
}

mol::state_block::state_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto type_l (tree_a.get<std::string> ("type"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = type_l != "state";
			if (!error_a)
			{
				error_a = mol::from_string_hex (work_l, work);
				if (!error_a)
				{
					error_a = signature.decode_hex (signature_l);
				}
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void mol::state_block::hash (blake2b_state & hash_a) const
{
	mol::uint256_union preamble (static_cast<uint64_t> (mol::block_type::state));
	blake2b_update (&hash_a, preamble.bytes.data (), preamble.bytes.size ());
	hashables.hash (hash_a);
}

uint64_t mol::state_block::block_work () const
{
	return work;
}

void mol::state_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

mol::block_hash mol::state_block::previous () const
{
	return hashables.previous;
}

void mol::state_block::serialize (mol::stream & stream_a) const
{
	write (stream_a, hashables.account);
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.balance);
	write (stream_a, hashables.link);
	write (stream_a, signature);
	write (stream_a, boost::endian::native_to_big (work));
}

void mol::state_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "state");
	tree.put ("account", hashables.account.to_account ());
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("balance", hashables.balance.to_string_dec ());
	tree.put ("link", hashables.link.to_string ());
	tree.put ("link_as_account", hashables.link.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	tree.put ("work", mol::to_string_hex (work));
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool mol::state_block::deserialize (mol::stream & stream_a)
{
	auto error (read (stream_a, hashables.account));
	if (!error)
	{
		error = read (stream_a, hashables.previous);
		if (!error)
		{
			error = read (stream_a, hashables.representative);
			if (!error)
			{
				error = read (stream_a, hashables.balance);
				if (!error)
				{
					error = read (stream_a, hashables.link);
					if (!error)
					{
						error = read (stream_a, signature);
						if (!error)
						{
							error = read (stream_a, work);
							boost::endian::big_to_native_inplace (work);
						}
					}
				}
			}
		}
	}
	return error;
}

bool mol::state_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "state");
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.account.decode_account (account_l);
		if (!error)
		{
			error = hashables.previous.decode_hex (previous_l);
			if (!error)
			{
				error = hashables.representative.decode_account (representative_l);
				if (!error)
				{
					error = hashables.balance.decode_dec (balance_l);
					if (!error)
					{
						error = hashables.link.decode_account (link_l) && hashables.link.decode_hex (link_l);
						if (!error)
						{
							error = mol::from_string_hex (work_l, work);
							if (!error)
							{
								error = signature.decode_hex (signature_l);
							}
						}
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void mol::state_block::visit (mol::block_visitor & visitor_a) const
{
	visitor_a.state_block (*this);
}

mol::block_type mol::state_block::type () const
{
	return mol::block_type::state;
}

bool mol::state_block::operator== (mol::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool mol::state_block::operator== (mol::state_block const & other_a) const
{
	return hashables.account == other_a.hashables.account && hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && hashables.balance == other_a.hashables.balance && hashables.link == other_a.hashables.link && signature == other_a.signature && work == other_a.work;
}

bool mol::state_block::valid_predecessor (mol::block const & block_a) const
{
	return true;
}

mol::block_hash mol::state_block::source () const
{
	return 0;
}

mol::block_hash mol::state_block::root () const
{
	return !hashables.previous.is_zero () ? hashables.previous : hashables.account;
}

mol::account mol::state_block::representative () const
{
	return hashables.representative;
}

mol::signature mol::state_block::block_signature () const
{
	return signature;
}

void mol::state_block::signature_set (mol::uint512_union const & signature_a)
{
	signature = signature_a;
}

std::unique_ptr<mol::block> mol::deserialize_block_json (boost::property_tree::ptree const & tree_a)
{
	std::unique_ptr<mol::block> result;
	try
	{
		auto type (tree_a.get<std::string> ("type"));
		if (type == "receive")
		{
			bool error;
			std::unique_ptr<mol::receive_block> obj (new mol::receive_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "send")
		{
			bool error;
			std::unique_ptr<mol::send_block> obj (new mol::send_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "open")
		{
			bool error;
			std::unique_ptr<mol::open_block> obj (new mol::open_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "change")
		{
			bool error;
			std::unique_ptr<mol::change_block> obj (new mol::change_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "state")
		{
			bool error;
			std::unique_ptr<mol::state_block> obj (new mol::state_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
	}
	catch (std::runtime_error const &)
	{
	}
	return result;
}

std::unique_ptr<mol::block> mol::deserialize_block (mol::stream & stream_a)
{
	mol::block_type type;
	auto error (read (stream_a, type));
	std::unique_ptr<mol::block> result;
	if (!error)
	{
		result = mol::deserialize_block (stream_a, type);
	}
	return result;
}

std::unique_ptr<mol::block> mol::deserialize_block (mol::stream & stream_a, mol::block_type type_a)
{
	std::unique_ptr<mol::block> result;
	switch (type_a)
	{
		case mol::block_type::receive:
		{
			bool error;
			std::unique_ptr<mol::receive_block> obj (new mol::receive_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case mol::block_type::send:
		{
			bool error;
			std::unique_ptr<mol::send_block> obj (new mol::send_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case mol::block_type::open:
		{
			bool error;
			std::unique_ptr<mol::open_block> obj (new mol::open_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case mol::block_type::change:
		{
			bool error;
			std::unique_ptr<mol::change_block> obj (new mol::change_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case mol::block_type::state:
		{
			bool error;
			std::unique_ptr<mol::state_block> obj (new mol::state_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		default:
			assert (false);
			break;
	}
	return result;
}

void mol::receive_block::visit (mol::block_visitor & visitor_a) const
{
	visitor_a.receive_block (*this);
}

bool mol::receive_block::operator== (mol::receive_block const & other_a) const
{
	auto result (hashables.previous == other_a.hashables.previous && hashables.source == other_a.hashables.source && work == other_a.work && signature == other_a.signature);
	return result;
}

bool mol::receive_block::deserialize (mol::stream & stream_a)
{
	auto error (false);
	error = read (stream_a, hashables.previous.bytes);
	if (!error)
	{
		error = read (stream_a, hashables.source.bytes);
		if (!error)
		{
			error = read (stream_a, signature.bytes);
			if (!error)
			{
				error = read (stream_a, work);
			}
		}
	}
	return error;
}

bool mol::receive_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "receive");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto source_l (tree_a.get<std::string> ("source"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.source.decode_hex (source_l);
			if (!error)
			{
				error = mol::from_string_hex (work_l, work);
				if (!error)
				{
					error = signature.decode_hex (signature_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void mol::receive_block::serialize (mol::stream & stream_a) const
{
	write (stream_a, hashables.previous.bytes);
	write (stream_a, hashables.source.bytes);
	write (stream_a, signature.bytes);
	write (stream_a, work);
}

void mol::receive_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "receive");
	std::string previous;
	hashables.previous.encode_hex (previous);
	tree.put ("previous", previous);
	std::string source;
	hashables.source.encode_hex (source);
	tree.put ("source", source);
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", mol::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

mol::receive_block::receive_block (mol::block_hash const & previous_a, mol::block_hash const & source_a, mol::raw_key const & prv_a, mol::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, source_a),
signature (mol::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

mol::receive_block::receive_block (bool & error_a, mol::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = mol::read (stream_a, signature);
		if (!error_a)
		{
			error_a = mol::read (stream_a, work);
		}
	}
}

mol::receive_block::receive_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = signature.decode_hex (signature_l);
			if (!error_a)
			{
				error_a = mol::from_string_hex (work_l, work);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void mol::receive_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t mol::receive_block::block_work () const
{
	return work;
}

void mol::receive_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

bool mol::receive_block::operator== (mol::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool mol::receive_block::valid_predecessor (mol::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case mol::block_type::send:
		case mol::block_type::receive:
		case mol::block_type::open:
		case mol::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

mol::block_hash mol::receive_block::previous () const
{
	return hashables.previous;
}

mol::block_hash mol::receive_block::source () const
{
	return hashables.source;
}

mol::block_hash mol::receive_block::root () const
{
	return hashables.previous;
}

mol::account mol::receive_block::representative () const
{
	return 0;
}

mol::signature mol::receive_block::block_signature () const
{
	return signature;
}

void mol::receive_block::signature_set (mol::uint512_union const & signature_a)
{
	signature = signature_a;
}

mol::block_type mol::receive_block::type () const
{
	return mol::block_type::receive;
}

mol::receive_hashables::receive_hashables (mol::block_hash const & previous_a, mol::block_hash const & source_a) :
previous (previous_a),
source (source_a)
{
}

mol::receive_hashables::receive_hashables (bool & error_a, mol::stream & stream_a)
{
	error_a = mol::read (stream_a, previous.bytes);
	if (!error_a)
	{
		error_a = mol::read (stream_a, source.bytes);
	}
}

mol::receive_hashables::receive_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto source_l (tree_a.get<std::string> ("source"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = source.decode_hex (source_l);
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void mol::receive_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, source.bytes.data (), sizeof (source.bytes));
}

//added by sandy - s
mol::astate_hashables::astate_hashables (mol::account const & account_a, mol::block_hash const & previous_a, mol::account const & representative_a, mol::amount const & balance_a, mol::uint256_union const & link_a, mol::asset const & asset_a, mol::account const & genesis_account_a) :
		account (account_a),
		previous (previous_a),
		representative (representative_a),
		balance (balance_a),
		link (link_a),

		asset(asset_a),
		genesis_account(genesis_account_a)
{
}

mol::astate_hashables::astate_hashables (bool & error_a, mol::stream & stream_a) {

	error_a = mol::read (stream_a, account);
	if (!error_a) {

		error_a = mol::read (stream_a, previous);
		if (!error_a) {

			error_a = mol::read (stream_a, representative);
			if (!error_a) {

				error_a = mol::read (stream_a, balance);
				if (!error_a) {

					error_a = mol::read (stream_a, link);
					if (!error_a) {

						error_a = mol::read (stream_a, asset);
						if (!error_a) {

							error_a = mol::read (stream_a, genesis_account);

						}

					}

				}
			}
		}
	}
}

mol::astate_hashables::astate_hashables (bool & error_a, boost::property_tree::ptree const & tree_a) {

	try {

		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));

		auto asset_l (tree_a.get<std::string> ("asset"));
		auto genesis_account_l (tree_a.get<std::string> ("genesis_account"));

		error_a = account.decode_account (account_l);
		if (!error_a) {

			error_a = previous.decode_hex (previous_l);
			if (!error_a) {

				error_a = representative.decode_account (representative_l);
				if (!error_a) {

					error_a = balance.decode_dec (balance_l);
					if (!error_a) {

						error_a = link.decode_account (link_l) && link.decode_hex (link_l);
						if (!error_a) {

							error_a = asset.decode_hex(asset_l);
							if (!error_a) {

								error_a = genesis_account.decode_account(genesis_account_l) && genesis_account.decode_hex(genesis_account_l);

							}

						}

					}
				}
			}
		}

	} catch (std::runtime_error const &) {

		error_a = true;
	}

}

void mol::astate_hashables::hash (blake2b_state & hash_a) const {

	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	blake2b_update (&hash_a, link.bytes.data (), sizeof (link.bytes));

	blake2b_update (&hash_a, asset.bytes.data(), sizeof (asset.bytes));
	blake2b_update (&hash_a, genesis_account.bytes.data(), sizeof (genesis_account.bytes));

}

mol::astate_block::astate_block (mol::account const & account_a, mol::block_hash const & previous_a, mol::account const & representative_a, mol::amount const & balance_a, mol::uint256_union const & link_a, mol::asset const & asset_a,  mol::account const & genesis_account_a, char const * identifier_a, mol::raw_key const & prv_a, mol::public_key const & pub_a, uint64_t work_a) :
		hashables (account_a, previous_a, representative_a, balance_a, link_a, asset_a, genesis_account_a),
		signature (mol::sign_message (prv_a, pub_a, hash ())),
		work (work_a)
{

	strcpy(identifier, identifier_a);
}

mol::astate_block::astate_block (bool & error_a, mol::stream & stream_a) :
		hashables (error_a, stream_a) {

	if (!error_a) {

		error_a = mol::read(stream_a, signature);
		if (!error_a) {

			error_a = mol::read(stream_a, work);
			boost::endian::big_to_native_inplace(work);

			if (!error_a) {

				error_a = mol::read_identifier(stream_a, identifier[0]);
				identifier[3] = 0;
			}
		}

	}


}

mol::astate_block::astate_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
		hashables (error_a, tree_a) {

	if (!error_a) {

		try {

			auto type_l (tree_a.get<std::string> ("type"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));

			auto identifier_l (tree_a.get<std::string> ("identifier"));

			error_a = type_l != "astate";

			if (!error_a) {

				error_a = mol::from_string_hex (work_l, work);
				if (!error_a) {

					error_a = signature.decode_hex (signature_l);
					if (!error_a) {

						strcpy(identifier, identifier_l.c_str());
						if (strlen(identifier) == 0) {

							error_a = true;

						} else {

							error_a = false;
						}

					}

				}
			}

		} catch (std::runtime_error const &) {

			error_a = true;
		}
	}
}

void mol::astate_block::hash (blake2b_state & hash_a) const
{
	mol::uint256_union preamble (static_cast<uint64_t> (mol::block_type::astate));
	blake2b_update (&hash_a, preamble.bytes.data (), preamble.bytes.size ());
	hashables.hash (hash_a);
}

uint64_t mol::astate_block::block_work () const
{
	return work;
}

void mol::astate_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

mol::block_hash mol::astate_block::previous () const
{
	return hashables.previous;
}

void mol::astate_block::serialize (mol::stream & stream_a) const
{
	write (stream_a, hashables.account);
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.balance);
	write (stream_a, hashables.link);

	write(stream_a, hashables.asset);
	write(stream_a, hashables.genesis_account);

	write (stream_a, signature);
	write (stream_a, boost::endian::native_to_big (work));
	write_identifier (stream_a, identifier[0]);
}

void mol::astate_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "astate");
	tree.put ("account", hashables.account.to_account ());
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("balance", hashables.balance.to_string_dec ());
	tree.put ("link", hashables.link.to_string ());
	tree.put ("link_as_account", hashables.link.to_account ());

	tree.put ("asset", hashables.asset.to_string());
	if (hashables.genesis_account.is_zero()) {
		tree.put("genesis_account", hashables.genesis_account.to_string());
	} else {
		tree.put("genesis_account", hashables.genesis_account.to_account());
	}

	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	tree.put ("work", mol::to_string_hex (work));

	std::string identifier_l = identifier;
	tree.put ("identifier", identifier_l);

	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();

	std::cout << "mol::astate_block::serialize_json next==" << string_a << "==end next" << std::endl;
}

bool mol::astate_block::deserialize (mol::stream & stream_a) {

	auto error (read (stream_a, hashables.account));
	if (!error) {

		error = read (stream_a, hashables.previous);
		if (!error) {

			error = read (stream_a, hashables.representative);
			if (!error) {

				error = read (stream_a, hashables.balance);
				if (!error) {

					error = read (stream_a, hashables.link);
					if (!error) {

						error = read (stream_a, hashables.asset);
						if (!error) {

							error = read(stream_a, hashables.genesis_account);
							if (!error) {

								error = read(stream_a, signature);
								if (!error) {

									error = read(stream_a, work);
									boost::endian::big_to_native_inplace(work);

									if (!error) {

										error = read_identifier(stream_a, identifier[0]);
										identifier[3] = 0;

									}

								}

							}



						}

					}
				}
			}
		}
	}
	return error;
}

bool mol::astate_block::deserialize_json (boost::property_tree::ptree const & tree_a) {

	auto error (false);
	try {

		assert (tree_a.get<std::string> ("type") == "astate");

		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));

		auto asset_l (tree_a.get<std::string> ("asset"));
		auto genesis_account_l (tree_a.get<std::string> ("genesis_account"));

		auto identifier_l (tree_a.get<std::string> ("identifier"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));

		error = hashables.account.decode_account (account_l);
		if (!error) {

			error = hashables.previous.decode_hex (previous_l);
			if (!error) {

				error = hashables.representative.decode_account (representative_l);
				if (!error) {

					error = hashables.balance.decode_dec (balance_l);
					if (!error) {

						error = hashables.link.decode_account (link_l) && hashables.link.decode_hex (link_l);
						if (!error) {

							error = hashables.asset.decode_hex(asset_l);
							if (!error) {

								error = hashables.genesis_account.decode_account(genesis_account_l) && hashables.genesis_account.decode_hex(genesis_account_l);
								if (!error) {

									strcpy(identifier, identifier_l.c_str());
									if (strlen(identifier) == 0) {
										error = true;
									} else {
										error = false;
									}

									if (!error) {

										error = mol::from_string_hex(work_l, work);
										if (!error) {

											error = signature.decode_hex(signature_l);
										}

									}

								}

							}

						}
					}
				}
			}
		}

	} catch (std::runtime_error const &) {

		error = true;
	}
	return error;
}

void mol::astate_block::visit (mol::block_visitor & visitor_a) const
{
	visitor_a.astate_block (*this);
}

mol::block_type mol::astate_block::type () const
{
	return mol::block_type::astate;
}

bool mol::astate_block::operator== (mol::block const & other_a) const {

	auto other_l (dynamic_cast<mol::astate_block const *> (&other_a));
	auto result (other_l != nullptr);
	if (result) {
		result = *this == *other_l;
	}
	return result;
}

bool mol::astate_block::operator== (mol::astate_block const & other_a) const {

	return hashables.account == other_a.hashables.account && hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && hashables.balance == other_a.hashables.balance && hashables.link == other_a.hashables.link && hashables.asset == other_a.hashables.asset && hashables.genesis_account == other_a.hashables.genesis_account && !strcmp(identifier, other_a.identifier) && signature == other_a.signature && work == other_a.work;
}

bool mol::astate_block::valid_predecessor (mol::block const & block_a) const
{
	return true;
}

mol::block_hash mol::astate_block::source () const
{
	return 0;
}

mol::block_hash mol::astate_block::root () const
{
	return !hashables.previous.is_zero () ? hashables.previous : hashables.account;
}

mol::account mol::astate_block::representative () const
{
	return hashables.representative;
}

mol::signature mol::astate_block::block_signature () const
{
	return signature;
}

std::string mol::astate_block::block_identifier () {

	//if (identifier && strlen(identifier) == 0) {
	//if (!identifier[0]) {
	//	return std::string("");
	//}
	std::string result = identifier;

	return  result;
}

void mol::astate_block::signature_set (mol::uint512_union const & signature_a)
{
	signature = signature_a;
}
//added by sandy - e
