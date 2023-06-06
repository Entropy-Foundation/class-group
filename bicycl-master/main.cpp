/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "bicycl.hpp"
using namespace BICYCL;

#include <iostream>
#include <unordered_set>
#include <vector>
#include <cstdlib> // for std::stoi function
#include "ctpl_stl.h"

int main (int argc, char* argv[])
{

  if (argc != 7) {
        std::cerr << "Expected 6 arguments (server/client, IP, Port, Total Nodes, Threshold, Multi-threaded), but got " << argc - 1 << std::endl;
        return 1;
  }

  std::string server_or_client = argv[1];  // "server" or "client"
  std::string ip_address = argv[2];        // IP address as string
  std::string port_str = argv[3];          // Port number as string
  std::string multi_threaded = argv[6];          // Port number as string
  unsigned int total_nodes;
  unsigned int threshold;
  short port;

  try {
        port = static_cast<short> (std::stoi(port_str));
        total_nodes = std::stoul(argv[4]);  // Convert string to int
        threshold = std::stoul(argv[5]);    // Convert string to int
    }
    catch(const std::invalid_argument& e) {
        std::cerr << "One or more of the numeric arguments are invalid." << std::endl;
        return 1;
    }


    if(server_or_client == "server"){

      DKG_Helper dkg_helper(total_nodes,threshold);
      DKG_Dealing dealing = dkg_helper.gen_test_dealing();
      protobuff_ser::Dealing dealing_bytes;
      dkg_helper.serialize_dealing(dealing, dealing_bytes);

      std::cout<<"Dealing generated"<<std::endl;

      dkg_helper.compute_benchmarks();

      std::cout<<"Waiting for connection!"<<std::endl;

      try
      {

        boost::asio::io_context io_context;
        // Initialize server
        server s(io_context, port, dealing_bytes, total_nodes);

        if(multi_threaded == "1"){

          // Create thread pool.
          std::vector<std::thread> thread_pool;
          auto num_threads = std::thread::hardware_concurrency();  // Get number of cores
          for (std::size_t i = 0; i < num_threads; ++i)
          {
              thread_pool.emplace_back([&io_context](){ io_context.run(); });
          }

          // Wait for all threads in the pool to exit.
          for (std::thread &t : thread_pool)
          {
              if (t.joinable())
              {
                  t.join();
              }
          }

        }
        else {

          io_context.run();

        }

      }
      catch (std::exception& e)
      {
        std::cerr << "Exception: " << e.what() << "\n";
      }

    }

    else if (server_or_client == "client"){

      if(multi_threaded == "1"){

        ctpl::thread_pool pool(10);  // create a thread pool with 10 threads
        std::vector<std::future<void>> results;
        for (unsigned int i = 0; i < total_nodes; ++i) {
            results.push_back(pool.push([&ip_address, &port_str, &total_nodes, &threshold](int) {
                client client(ip_address, port_str, total_nodes, threshold);
                client.run();
            }));
        }

        // Wait for all tasks to complete
        for(auto &result : results) {
            result.get();
        }
      }

      else{

        client client(ip_address, port_str, total_nodes, threshold);
        client.run();

      }

    }

    else {
      std::cerr << "First argument must be either server or client" << std::endl;
        return 1;
    }


  return EXIT_SUCCESS;
}
