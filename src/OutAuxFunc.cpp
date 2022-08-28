/*
 Copyright 2022 Yury Bobylev <bobilev_yury@mail.ru>

 This file is part of libcommunist.
 libcommunist is free software: you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation, either version 3 of
 the License, or (at your option) any later version.
 libcommunist is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with libcommunist. If not,
 see <https://www.gnu.org/licenses/>.
 */

#include <OutAuxFunc.h>

OutAuxFunc::OutAuxFunc ()
{
  // TODO Auto-generated constructor stub

}

OutAuxFunc::~OutAuxFunc ()
{
  // TODO Auto-generated destructor stub
}

std::array<char, 32>
OutAuxFunc::seedGenerate ()
{
  std::array<char, 32> seed = lt::dht::ed25519_create_seed ();
  return seed;
}

std::string
OutAuxFunc::getKeyFmSeed (std::array<char, 32> &seed)
{
  lt::dht::public_key pk;
  lt::dht::secret_key sk;
  std::tie (pk, sk) = lt::dht::ed25519_create_keypair (seed);
  std::string keystr = lt::aux::to_hex (pk.bytes);
  return keystr;
}

std::string
OutAuxFunc::getSecreteKeyFmSeed (std::array<char, 32> &seed)
{
  lt::dht::public_key pk;
  lt::dht::secret_key sk;
  std::tie (pk, sk) = lt::dht::ed25519_create_keypair (seed);
  std::string keystr = lt::aux::to_hex (sk.bytes);
  return keystr;
}

std::string
OutAuxFunc::genPasswd (std::string key, std::array<char, 32> &seed)
{
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkeypair;
  ownkeypair = lt::dht::ed25519_create_keypair (seed);
  lt::dht::public_key otherpk;
  std::array<char, 32> scalar;
  lt::aux::from_hex (key, otherpk.bytes.data ());
  scalar = lt::dht::ed25519_key_exchange (otherpk, std::get<1> (ownkeypair));
  lt::dht::public_key pkpass = lt::dht::ed25519_add_scalar (
      std::get<0> (ownkeypair), scalar);
  std::string passwd = lt::aux::to_hex (pkpass.bytes);
  return passwd;
}

std::string
OutAuxFunc::genFriendPasswd (std::string key, std::array<char, 32> &seed)
{
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkeypair;
  ownkeypair = lt::dht::ed25519_create_keypair (seed);
  lt::dht::public_key otherpk;
  std::array<char, 32> scalar;
  lt::aux::from_hex (key, otherpk.bytes.data ());
  scalar = lt::dht::ed25519_key_exchange (otherpk, std::get<1> (ownkeypair));
  lt::dht::public_key pkpass = lt::dht::ed25519_add_scalar (otherpk, scalar);
  std::string passwd = lt::aux::to_hex (pkpass.bytes);
  return passwd;
}

int
OutAuxFunc::createProfile (
    std::string Username, std::string Password, std::string homepath,
    std::vector<std::tuple<std::string, std::string>> &profvect,
    std::array<char, 32> &seed)
{
  int result = 0;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::string rndm = filename;
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  filename = filename + "/Profile";
  filepath = std::filesystem::u8path (filename);
  std::filesystem::create_directories (filepath);
  filename = filename + "/Profile";
  filepath = std::filesystem::u8path (filename);
  std::fstream f;
  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  std::string line;
  auto itprv = std::find_if (profvect.begin (), profvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Nick";
    });
  if (itprv != profvect.end ())
    {
      line = std::get<1> (*itprv);
      if (line != "")
	{
	  line = line + "\n";
	  f.write (line.c_str (), line.size ());
	}
      else
	{
	  return -1;
	}
    }
  else
    {
      return -1;
    }
  itprv = std::find_if (profvect.begin (), profvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Name";
    });
  if (itprv != profvect.end ())
    {
      line = std::get<1> (*itprv);
      if (line != "")
	{
	  line = line + "\n";
	  f.write (line.c_str (), line.size ());
	}
    }
  itprv = std::find_if (profvect.begin (), profvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Surname";
    });
  if (itprv != profvect.end ())
    {
      line = std::get<1> (*itprv);
      if (line != "")
	{
	  line = line + "\n";
	  f.write (line.c_str (), line.size ());
	}
    }
  f.close ();
  filename = rndm;
  filename = filename + "/Profile/Key";
  filepath = std::filesystem::u8path (filename);
  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  f.write (seed.data (), seed.size ());
  f.close ();
  itprv = std::find_if (profvect.begin (), profvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Avatar";
    });
  if (itprv != profvect.end ())
    {
      line = std::get<1> (*itprv);
      std::filesystem::path avpath = std::filesystem::u8path (line);
      filename = rndm;
      filename = filename + "/Profile/Avatar.jpeg";
      filepath = std::filesystem::u8path (filename);
      std::error_code ec;
      std::filesystem::copy (avpath, filepath, ec);
      if (ec.value () != 0)
	{
	  std::cerr << "Avatar error: " << ec.message () << std::endl;
	  result = 0;
	}
      else
	{
	  result = 1;
	}
    }
  std::string outfile = rndm;
  outfile = outfile + "/Profile.zip";
  filename = rndm;
  filename = filename + "/Profile";
  AuxFuncNet afn;
  int respack = afn.packing (filename, outfile);
  if (respack < 0)
    {
      std::cerr << "Profile packing failed!" << std::endl;
    }
  filepath = std::filesystem::u8path (filename);
  std::filesystem::remove_all (filepath);
  filename = homepath + "/.Communist/Profile";
  filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  afn.cryptFile (Username, Password, outfile, filename);

  filename = rndm;
  filepath = std::filesystem::u8path (filename);
  std::filesystem::remove_all (filepath);

  return result;
}

int
OutAuxFunc::openProfile (std::string homepath, std::string Username,
			 std::string Password, std::string outfoldername)
{
  int result = 0;
  std::string filename = homepath + "/.Communist/Profile";
  std::string outfile = outfoldername;
  std::filesystem::path source = std::filesystem::u8path (filename);
  std::filesystem::path outpath = std::filesystem::u8path (outfile);
  if (!std::filesystem::exists (source))
    {
      std::cerr << "Profile file does not exists!" << std::endl;
      result = -1;
    }
  else
    {
      if (std::filesystem::exists (outpath))
	{
	  std::filesystem::remove_all (outpath);
	}
      std::filesystem::create_directories (outpath);
      AuxFuncNet afn;
      afn.decryptFile (Username, Password, source.u8string (),
		       outpath.u8string () + "/Profile.zip");
      if (afn.unpacking (outpath.u8string () + "/Profile.zip",
			 outpath.u8string ()) >= 0)
	{
	  result = 1;
	  filename = outpath.u8string () + "/Profile.zip";
	  source = std::filesystem::u8path (filename);
	  std::filesystem::remove_all (source);
	}
    }

  return result;
}

int
OutAuxFunc::editProfile (
    std::string Username, std::string Password, std::string homepath,
    std::vector<std::tuple<std::string, std::vector<char>>> &profvect,
    std::array<char, 32> &seed,
    std::vector<std::tuple<int, std::string>> &contacts,
    std::vector<std::string> &Addfriends,
    std::vector<std::string> &relaycontlist)
{
  int result = 0;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::string rndm = filename;
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  filename = filename + "/Profile";
  filepath = std::filesystem::u8path (filename);
  std::filesystem::create_directories (filepath);
  filename = filename + "/Profile";
  filepath = std::filesystem::u8path (filename);
  std::fstream f;
  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  std::string line;
  std::vector<char> val;
  if (f.is_open ())
    {
      auto itprv = std::find_if (profvect.begin (), profvect.end (), []
      (auto &el)
	{
	  return std::get<0>(el) == "Nick";
	});
      if (itprv != profvect.end ())
	{
	  val = std::get<1> (*itprv);
	  if (val.size () > 0)
	    {
	      std::copy (val.begin (), val.end (), std::back_inserter (line));
	      line = line + "\n";
	      f.write (line.c_str (), line.size ());
	    }
	  else
	    {
	      f.close ();
	      return -1;
	    }
	}
      else
	{
	  f.close ();
	  return -1;
	}
      itprv = std::find_if (profvect.begin (), profvect.end (), []
      (auto &el)
	{
	  return std::get<0>(el) == "Name";
	});
      if (itprv != profvect.end ())
	{
	  val = std::get<1> (*itprv);
	  line.clear ();
	  if (val.size () > 0)
	    {
	      std::copy (val.begin (), val.end (), std::back_inserter (line));
	      line = line + "\n";
	      f.write (line.c_str (), line.size ());
	    }
	}
      itprv = std::find_if (profvect.begin (), profvect.end (), []
      (auto &el)
	{
	  return std::get<0>(el) == "Surname";
	});
      if (itprv != profvect.end ())
	{
	  val = std::get<1> (*itprv);
	  line.clear ();
	  if (val.size () > 0)
	    {
	      std::copy (val.begin (), val.end (), std::back_inserter (line));
	      line = line + "\n";
	      f.write (line.c_str (), line.size ());
	    }
	}
      f.close ();
    }
  else
    {
      return -1;
    }
  filename = rndm;
  filename = filename + "/Profile/Key";
  filepath = std::filesystem::u8path (filename);
  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  if (f.is_open ())
    {
      f.write (seed.data (), seed.size ());
      f.close ();
    }
  else
    {
      return -1;
    }
  if (contacts.size () > 0)
    {
      filename = filepath.parent_path ().u8string ();
      filename = filename + "/Contacts";
      filepath = std::filesystem::u8path (filename);
      f.open (filepath, std::ios_base::out | std::ios_base::binary);
      for (size_t i = 0; i < contacts.size (); i++)
	{
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue (loc);
	  strm << std::get<0> (contacts[i]);
	  line = strm.str () + " " + std::get<1> (contacts[i]) + "\n";
	  f.write (line.c_str (), line.size ());
	}
      f.close ();
    }
  if (Addfriends.size () > 0)
    {
      filename = filepath.parent_path ().u8string ();
      filename = filename + "/RequestList";
      filepath = std::filesystem::u8path (filename);
      f.open (filepath, std::ios_base::out | std::ios_base::binary);
      for (size_t i = 0; i < Addfriends.size (); i++)
	{
	  line = Addfriends[i];
	  line = line + "\n";
	  f.write (line.c_str (), line.size ());
	}
      f.close ();
    }

  if (relaycontlist.size () > 0)
    {
      filename = rndm;
      filename = filename + "/Profile/RelayContacts";
      filepath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (filepath))
	{
	  std::filesystem::remove_all (filepath);
	}
      f.open (filepath, std::ios_base::out | std::ios_base::binary);
      for (size_t i = 0; i < relaycontlist.size (); i++)
	{
	  std::string line = relaycontlist[i];
	  line = line + "\n";
	  f.write (line.c_str (), line.size ());
	}
      f.close ();
    }

  auto itprv = std::find_if (profvect.begin (), profvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Avatar";
    });
  if (itprv != profvect.end ())
    {
      val = std::get<1> (*itprv);
      filename = rndm;
      filename = filename + "/Profile/Avatar.jpeg";
      filepath = std::filesystem::u8path (filename);
      if (val.size () > 0)
	{
	  f.open (filepath, std::ios_base::out | std::ios_base::binary);
	  if (f.is_open ())
	    {
	      f.write (&val[0], val.size ());
	      f.close ();
	      result = 1;
	    }
	  else
	    {
	      result = 0;
	    }
	}
      else
	{
	  result = 0;
	}
    }
  else
    {
      result = 1;
    }
  std::string outfile = rndm;
  outfile = outfile + "/Profile.zip";
  filename = rndm;
  filename = filename + "/Profile";
  AuxFuncNet afn;
  int respack = afn.packing (filename, outfile);
  if (respack < 0)
    {
      std::cerr << "Profile packing failed!" << std::endl;
      result = -1;
    }
  filepath = std::filesystem::u8path (filename);
  std::filesystem::remove_all (filepath);
  filename = homepath + "/.Communist/Profile";
  filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  afn.cryptFile (Username, Password, outfile, filename);
  if (!std::filesystem::exists (filepath))
    {
      result = -1;
    }
  else
    {
      if (result > 0)
	{
	  result = 1;
	}
      else
	{
	  result = 0;
	}
    }
  filename = rndm;
  filepath = std::filesystem::u8path (filename);
  std::filesystem::remove_all (filepath);

  return result;
}

std::vector<std::tuple<int, std::string>>
OutAuxFunc::readContacts (std::string homepath, std::string Username,
			  std::string Password)
{
  std::vector<std::tuple<int, std::string>> resvect;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::string rndm = filename;
  int result = openProfile (homepath, Username, Password, filename);
  if (result >= 0)
    {
      filename = filename + "/Profile/Contacts";
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      std::fstream f;
      f.open (filepath, std::ios_base::in);
      if (f.is_open ())
	{
	  while (!f.eof ())
	    {
	      std::string line;
	      getline (f, line);
	      if (line != "")
		{
		  std::string indline = line;
		  indline = indline.substr (0, indline.find (" "));
		  std::stringstream strm;
		  std::locale loc ("C");
		  strm.imbue (loc);
		  strm << indline;
		  int ind;
		  strm >> ind;
		  std::tuple<int, std::string> ttup;
		  std::get<0> (ttup) = ind;
		  indline = line;
		  indline.erase (
		      0, indline.find (" ") + std::string (" ").size ());
		  std::get<1> (ttup) = indline;
		  resvect.push_back (ttup);
		}
	    }
	  f.close ();
	}
      else
	{
	  std::cerr << "Contacts file not opened!" << std::endl;
	}
    }
  else
    {
      std::cerr << "Contacts read profile failure!" << std::endl;
    }
  filename = rndm;
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  std::filesystem::remove_all (filepath);

  return resvect;
}

std::vector<std::string>
OutAuxFunc::readRequestList (std::string homepath, std::string Username,
			     std::string Password)
{
  std::vector<std::string> resvect;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::string rndm = filename;
  int result = openProfile (homepath, Username, Password, filename);
  if (result >= 0)
    {
      filename = filename + "/Profile/RequestList";
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      std::fstream f;
      f.open (filepath, std::ios_base::in);
      if (f.is_open ())
	{
	  while (!f.eof ())
	    {
	      std::string line;
	      getline (f, line);
	      if (!line.empty ())
		{
		  resvect.push_back (line);
		}
	    }
	  f.close ();
	}
      else
	{
	  std::cerr << "RequestList file not opened!" << std::endl;
	}
    }
  else
    {
      std::cerr << "Profile requestList error!" << std::endl;
    }
  filename = rndm;
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  std::filesystem::remove_all (filepath);

  return resvect;
}

std::string
OutAuxFunc::getContactMsgLog (std::string homepath, std::string Username,
			      std::string Password, int contind,
			      std::string outfolderpath)
{
  std::stringstream strm;
  std::locale loc ("C");
  std::string index;
  strm.imbue (loc);
  strm << contind;
  index = strm.str ();
  std::string filename = homepath + "/.Communist/" + index + "/Yes";
  std::filesystem::path source = std::filesystem::u8path (filename);
  filename = outfolderpath + "/MsgLog";
  std::filesystem::path out = std::filesystem::u8path (filename);
  if (std::filesystem::exists (source))
    {
      if (std::filesystem::exists (out.parent_path ()))
	{
	  std::filesystem::remove_all (out.parent_path ());
	}
      std::filesystem::create_directories (out.parent_path ());
      AuxFuncNet afn;
      afn.decryptFile (Username, Password, source.u8string (), out.u8string ());
    }
  return out.u8string ();
}

int
OutAuxFunc::openFriendProfile (std::string homepath, std::array<char, 32> &seed,
			       std::string friendkey, int ind,
			       std::string outfoldername)
{
  int result = 0;
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << ind;
  std::string filename = homepath + "/.Communist/" + strm.str () + "/Profile";
  std::filesystem::path source = std::filesystem::u8path (filename);
  filename = outfoldername + "/Profile.zip";
  std::filesystem::path outpath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (outpath.parent_path ()))
    {
      std::filesystem::remove_all (outpath.parent_path ());
    }
  std::filesystem::create_directories (outpath.parent_path ());
  std::string uname = getKeyFmSeed (seed);
  std::string passwd = genPasswd (friendkey, seed);
  AuxFuncNet afn;
  afn.decryptFile (uname, passwd, source.u8string (), outpath.u8string ());
  result = afn.unpacking (outpath.u8string (),
			  outpath.parent_path ().u8string ());
  if (result >= 0)
    {
      result = 1;
    }
  else
    {
      result = -1;
    }
  std::filesystem::remove_all (outpath);

  return result;
}

void
OutAuxFunc::msgAutoRemove (std::string homepath, std::string Username,
			   std::string Password, std::string mode)
{
  AuxFuncNet afn;
  std::string filename = homepath + "/.Communist";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      for (auto &cdirit : std::filesystem::directory_iterator (filepath))
	{
	  std::filesystem::path p = cdirit.path ();
	  if (std::filesystem::is_directory (p)
	      && p.filename ().u8string () != "SendBufer"
	      && p.filename ().u8string () != "Bufer")
	    {
	      std::vector<std::filesystem::path> msgs;
	      for (auto dirit : std::filesystem::directory_iterator (p))
		{
		  std::filesystem::path p2 = dirit.path ();
		  if (p2.filename ().u8string () != "Profile"
		      && p2.filename ().u8string () != "Yes")
		    {
		      msgs.push_back (p2);
		    }
		}
	      std::sort (msgs.begin (), msgs.end (), []
	      (auto &el1, auto &el2)
		{
		  std::stringstream strm;
		  std::locale loc ("C");
		  strm.imbue(loc);
		  std::string f = el1.filename().u8string();
		  f = f.substr(0, f.find("f"));
		  std::string s = el2.filename().u8string();
		  s = s.substr(0, s.find("f"));
		  int fi;
		  strm << f;
		  strm >> fi;
		  strm.clear();
		  strm.str("");
		  strm.imbue(loc);
		  int si;
		  strm << s;
		  strm >> si;
		  return fi < si;
		});
	      filename = p.u8string ();
	      filename = filename + "/Yes";
	      std::filesystem::path sp = std::filesystem::u8path (filename);
	      if (std::filesystem::exists (sp))
		{
#ifdef __linux
		  filename =
		      std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
		  filename =
		      std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
		  filename = filename + "/" + randomFileName () + "/Yes";
		  std::filesystem::path outpath = std::filesystem::u8path (
		      filename);
		  if (std::filesystem::exists (outpath.parent_path ()))
		    {
		      std::filesystem::remove_all (outpath.parent_path ());
		    }
		  std::filesystem::create_directories (outpath.parent_path ());
		  afn.decryptFile (Username, Password, sp.u8string (),
				   outpath.u8string ());
		  std::vector<std::tuple<std::string, uint64_t>> yesv;
		  std::fstream f;
		  f.open (outpath, std::ios_base::in);
		  int count = 0;
		  std::string key;
		  while (!f.eof ())
		    {
		      std::string line;
		      getline (f, line);
		      if (line != "" && count > 0)
			{
			  std::tuple<std::string, uint64_t> ttup;
			  std::string tstr = line;
			  tstr = tstr.substr (0, tstr.find (" "));
			  std::get<0> (ttup) = tstr;
			  tstr = line;
			  tstr.erase (
			      0, tstr.find (" ") + std::string (" ").size ());
			  std::stringstream strm;
			  std::locale loc ("C");
			  strm.imbue (loc);
			  strm << tstr;
			  uint64_t tm;
			  strm >> tm;
			  std::get<1> (ttup) = tm;
			  yesv.push_back (ttup);
			}
		      if (count == 0)
			{
			  key = line;
			  key = key + "\n";
			}
		      count++;
		    }
		  f.close ();
		  uint64_t dif;
		  time_t curtime = time (NULL);
		  if (mode == "1")
		    {
		      dif = 24 * 3600;
		    }
		  if (mode == "2")
		    {
		      dif = 7 * 24 * 3600;
		    }
		  if (mode == "3")
		    {
		      dif = 31 * 24 * 3600;
		    }
		  if (mode == "4")
		    {
		      dif = 365 * 24 * 3600;
		    }
		  yesv.erase (
		      std::remove_if (
			  yesv.begin (), yesv.end (), [&dif, &curtime]
			  (auto &el)
			    {
			      return std::get<1>(el) < curtime - dif;
			    }),
		      yesv.end ());
		  if (yesv.size () > 0)
		    {
		      std::string lessrm = std::get<0> (yesv[0]);
		      std::stringstream strm;
		      std::locale loc ("C");
		      strm.imbue (loc);
		      strm << lessrm;
		      int lrm;
		      strm >> lrm;
		      msgs.erase (
			  std::remove_if (msgs.begin (), msgs.end (), [&lrm]
			  (auto &el)
			    {
			      std::string fnm = el.filename().u8string();
			      fnm = fnm.substr(0, fnm.find ("f"));
			      std::stringstream strm;
			      std::locale loc ("C");
			      strm.imbue(loc);
			      strm << fnm;
			      int l;
			      strm >> l;
			      if (l < lrm)
				{
				  std::filesystem::remove_all (el);
				  return true;
				}
			      else
				{
				  return false;
				}
			    }),
			  msgs.end ());
		      for (size_t i = 0; i < msgs.size (); i++)
			{
			  filename = msgs[i].filename ().u8string ();
			  std::string::size_type n;
			  n = filename.find ("f");
			  strm.clear ();
			  strm.str ("");
			  strm.imbue (loc);
			  strm << i;
			  filename = msgs[i].parent_path ().u8string () + "/"
			      + strm.str ();
			  if (n != std::string::npos)
			    {
			      filename = filename + "f";
			    }
			  std::filesystem::path rnm = std::filesystem::u8path (
			      filename);
			  std::filesystem::rename (msgs[i], rnm);
			}
		      f.open (outpath,
			      std::ios_base::out | std::ios_base::binary);
		      f.write (key.c_str (), key.size ());
		      for (size_t i = 0; i < yesv.size (); i++)
			{
			  strm.clear ();
			  strm.str ("");
			  strm.imbue (loc);
			  strm << i;
			  std::string line;
			  line = strm.str ();
			  strm.clear ();
			  strm.str ("");
			  strm.imbue (loc);
			  strm << std::get<1> (yesv[i]);
			  line = line + " " + strm.str () + "\n";
			  f.write (line.c_str (), line.size ());
			}
		      f.close ();
		      f.open (outpath, std::ios_base::in);
		      while (!f.eof ())
			{
			  std::string line;
			  getline (f, line);
			}
		      f.close ();
		      afn.cryptFile (Username, Password, outpath.u8string (),
				     sp.u8string ());
		    }
		  else
		    {
		      for (size_t i = 0; i < msgs.size (); i++)
			{
			  std::filesystem::remove_all (msgs[i]);
			}
		      std::filesystem::remove_all (sp);
		    }
		  std::filesystem::remove_all (outpath.parent_path ());
		}
	    }
	}
    }
}

std::vector<std::tuple<std::string, std::vector<char>>>
OutAuxFunc::readProfile (std::string homepath, std::string Username,
			 std::string Password)
{
  std::vector<std::tuple<std::string, std::vector<char>>> profvect;

  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::string rndm = filename;
  openProfile (homepath, Username, Password, filename);
  filename = filename + "/Profile/Profile";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  std::fstream f;
  f.open (filepath, std::ios_base::in);
  if (!f.is_open ())
    {
      std::cerr << "Profile file not opened!" << std::endl;
    }
  else
    {
      int count = 0;
      while (!f.eof ())
	{
	  std::string line;
	  getline (f, line);
	  if (!line.empty ())
	    {
	      std::tuple<std::string, std::vector<char>> ttup;
	      if (count == 0)
		{
		  std::get<0> (ttup) = "Nick";
		}
	      if (count == 1)
		{
		  std::get<0> (ttup) = "Name";
		}
	      if (count == 2)
		{
		  std::get<0> (ttup) = "Surname";
		}
	      std::vector<char> val;
	      std::copy (line.begin (), line.end (), std::back_inserter (val));
	      std::get<1> (ttup) = val;
	      profvect.push_back (ttup);
	    }
	  count++;
	}
      f.close ();
    }
  filename = filepath.parent_path ().u8string ();
  filename = filename + "/Avatar.jpeg";
  filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      int filesize = std::filesystem::file_size (filepath);
      if (filesize > 0)
	{
	  std::vector<char> val;
	  val.resize (filesize);
	  f.open (filepath, std::ios_base::in | std::ios_base::binary);
	  if (f.is_open ())
	    {
	      f.read (&val[0], val.size ());
	      f.close ();
	      profvect.push_back (std::make_tuple ("Avatar", val));
	    }
	}
    }
  filepath = std::filesystem::u8path (rndm);
  std::filesystem::remove_all (filepath);

  return profvect;
}

int
OutAuxFunc::readSeed (std::string homepath, std::string Username,
		      std::string Password, std::array<char, 32> &seed)
{
  int result = 0;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  openProfile (homepath, Username, Password, filename);
  filename = filename + "/Profile/Key";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  std::fstream f;
  f.open (filepath, std::ios_base::in | std::ios_base::binary);
  if (!f.is_open ())
    {
      std::cerr << "Seed file not opened" << std::endl;
      result = -1;
    }
  else
    {
      f.read (&seed[0], seed.size ());
      f.close ();
      result = 1;
    }
  std::filesystem::remove_all (filepath.parent_path ().parent_path ());

  return result;
}

std::vector<std::tuple<std::string, std::vector<char>>>
OutAuxFunc::readFriendProfile (
    std::string homepath, std::array<char, 32> &seed, std::string friendkey,
    std::vector<std::tuple<int, std::string>> &contacts)
{
  std::vector<std::tuple<std::string, std::vector<char>>> profvect;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::string rndm = filename;
  int index;
  auto itcont = std::find_if (contacts.begin (), contacts.end (), [friendkey]
  (auto &el)
    {
      return std::get<1>(el) == friendkey;
    });
  if (itcont != contacts.end ())
    {
      index = std::get<0> (*itcont);
      int result = openFriendProfile (homepath, seed, friendkey, index,
				      filename);
      if (result >= 0)
	{
	  filename = filename + "/Profile/Profile";
	  std::filesystem::path filepath = std::filesystem::u8path (filename);
	  std::fstream f;
	  f.open (filepath, std::ios_base::in);
	  if (!f.is_open ())
	    {
	      std::cerr << "Friend's profile not opened!" << std::endl;
	    }
	  else
	    {
	      int count = 0;
	      while (!f.eof ())
		{
		  std::string line;
		  getline (f, line);
		  if (!line.empty ())
		    {
		      std::tuple<std::string, std::vector<char>> ttup;
		      if (count == 0)
			{
			  std::get<0> (ttup) = "Nick";
			}
		      if (count == 1)
			{
			  std::get<0> (ttup) = "Name";
			}
		      if (count == 2)
			{
			  std::get<0> (ttup) = "Surname";
			}
		      std::vector<char> val;
		      std::copy (line.begin (), line.end (),
				 std::back_inserter (val));
		      std::get<1> (ttup) = val;
		      profvect.push_back (ttup);
		    }
		  count++;
		}
	      f.close ();
	      filename = filepath.parent_path ().u8string ();
	      filename = filename + "/Avatar.jpeg";
	      filepath = std::filesystem::u8path (filename);
	      if (std::filesystem::exists (filepath))
		{
		  int filesize = std::filesystem::file_size (filepath);
		  if (filesize > 0)
		    {
		      std::vector<char> val;
		      val.resize (filesize);
		      std::fstream f;
		      f.open (filepath,
			      std::ios_base::in | std::ios_base::binary);
		      if (f.is_open ())
			{
			  f.read (&val[0], val.size ());
			  f.close ();
			  profvect.push_back (std::make_tuple ("Avatar", val));
			}
		    }
		}
	    }
	}
    }
  std::filesystem::path filepath = std::filesystem::u8path (rndm);
  std::filesystem::remove_all (filepath);
  return profvect;
}

std::string
OutAuxFunc::openFriendMsg (std::filesystem::path msgpath, std::string friendkey,
			   std::array<char, 32> &seed)
{
  std::string outmsg;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::filesystem::path outpath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (outpath))
    {
      std::filesystem::remove_all (outpath);
    }
  outmsg = outpath.u8string ();
  std::string uname = getKeyFmSeed (seed);
  std::string passwd = genPasswd (friendkey, seed);
  AuxFuncNet afn;
  afn.decryptFile (uname, passwd, msgpath.u8string (), outpath.u8string ());

  return outmsg;
}

std::string
OutAuxFunc::openOwnMsg (std::filesystem::path msgpath, std::string friendkey,
			std::array<char, 32> &seed)
{
  std::string outmsg;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  std::filesystem::path outpath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (outpath))
    {
      std::filesystem::remove_all (outpath);
    }

  outmsg = outpath.u8string ();
  std::string uname = friendkey;
  std::string passwd = genFriendPasswd (friendkey, seed);
  AuxFuncNet afn;
  afn.decryptFile (uname, passwd, msgpath.u8string (), outpath.u8string ());
  return outmsg;
}

std::vector<std::filesystem::path>
OutAuxFunc::listMessages (std::string homepath, std::string key,
			  std::vector<std::tuple<int, std::string>> &contacts)
{
  std::vector<std::filesystem::path> result;
  auto itcont = std::find_if (contacts.begin (), contacts.end (), [key]
  (auto &el)
    {
      return std::get<1>(el) == key;
    });
  if (itcont != contacts.end ())
    {
      int ind = std::get<0> (*itcont);
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << ind;
      std::string filename = homepath;
      filename = filename + "/.Communist/" + strm.str ();
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      if (!std::filesystem::exists (filepath))
	{
	  std::cerr << "No messages found!" << std::endl;
	}
      else
	{
	  for (auto &dirit : std::filesystem::directory_iterator (filepath))
	    {
	      std::filesystem::path p = dirit.path ();
	      if (p.filename ().u8string () != "Profile"
		  && p.filename ().u8string () != "Yes")
		{
		  result.push_back (p);
		}
	    }
	}
    }
  return result;
}

std::vector<std::string>
OutAuxFunc::readRelayContacts (std::string homepath, std::string Username,
			       std::string Password)
{
  std::vector<std::string> result;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + randomFileName ();
  openProfile (homepath, Username, Password, filename);
  filename = filename + "/Profile/RelayContacts";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  std::fstream f;
  f.open (filepath, std::ios_base::in);
  if (!f.is_open ())
    {
      std::cerr << "RelayContacts file not opened" << std::endl;
    }
  else
    {
      while (!f.eof ())
	{
	  std::string line;
	  getline (f, line);
	  if (!line.empty ())
	    {
	      result.push_back (line);
	    }
	}
      f.close ();
    }
  std::filesystem::remove_all (filepath.parent_path ().parent_path ());

  return result;
}

std::string
OutAuxFunc::randomFileName ()
{
  std::string result;
  int rnd = std::rand ();
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << std::hex << rnd;
  result = strm.str () + "comm";
  return result;
}
