#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include "dealing.pb.h"
#include "DKG.hpp"
#include <atomic>
#include <chrono>
using boost::asio::ip::tcp;
using namespace BICYCL;

std::atomic<unsigned int> acks_received(0);
std::chrono::high_resolution_clock::time_point start;
std::chrono::high_resolution_clock::time_point end;

  // Function to start the timer
  void startTimer() {
    start = std::chrono::high_resolution_clock::now();
  }

  // Function to stop the timer and print the execution time
  void stopTimer() {
      end = std::chrono::high_resolution_clock::now();

      // Compute the duration in seconds
      std::chrono::duration<double> duration = end - start;
      double seconds = duration.count();

      std::cout << "Execution time: " << seconds << " seconds" << std::endl;
  }


class session
  : public std::enable_shared_from_this<session>
{
public:
  session(tcp::socket socket, unsigned int total_nodes)
    : total_nodes(total_nodes), socket_(std::move(socket))
  {
  }

  void start(protobuff_ser::Dealing& dealing_bytes)
  {
    send_dealing(dealing_bytes);
  }

private:
  unsigned int total_nodes;

  void receive_ack()
  {
    boost::asio::streambuf receive_buffer;  // Dynamic buffer to store received data

    auto self(shared_from_this());

    const std::string delimiter = "\r\n\r\n";
    boost::system::error_code error;


    // Read data into the dynamic buffer until the end of the stream
    boost::asio::read_until(socket_, receive_buffer, delimiter, error);

    if (!error)
        {

          std::string received_data(boost::asio::buffers_begin(receive_buffer.data()),
                 boost::asio::buffers_end(receive_buffer.data()) - delimiter.size());

          if(received_data == "Ack"){
            acks_received.fetch_add(1);

            /*if(acks_received == total_nodes){
              stopTimer();
              exit(0);
            }*/

            stopTimer();
            exit(0);





            //std::cout<<"Ack received: "<<acks_received<<std::endl;
          }
          else {
            std::cout << "Error in receiving ack. Received msg: " << received_data <<" size: "<<received_data.length()<<std::endl;
          }

      }

      else {
          std::cerr << "Error in receiving ack: " << error.message() << std::endl;
      }

  }


  void send_dealing(protobuff_ser::Dealing& dealing_bytes)
  {

    // Serialize the Dealing object
    std::string serializedDealing;
    dealing_bytes.SerializeToString(&serializedDealing);
    const std::string delimiter = "\r\n\r\n";

    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(serializedDealing + delimiter),
        [this, self](boost::system::error_code ec, std::size_t)
        {
          if (!ec)
          {
            receive_ack();
          }
        });
  }



  tcp::socket socket_;
};

class server
{
public:
  server(boost::asio::io_context& io_context, short port, protobuff_ser::Dealing& dealing_bytes, unsigned int total_nodes)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), dealing_bytes(dealing_bytes), total_nodes(total_nodes)
  {
    is_first_connection.store(true);
    //std::cout<<"Waiting for connections!"<<std::endl;
    do_accept();
  }

private:
  void do_accept()
  {

    acceptor_.async_accept(
      [this](boost::system::error_code ec, tcp::socket socket)
      {
        if (!ec)
        {

          bool flag = is_first_connection.load();

          if(flag){
            is_first_connection.store(false);
            startTimer();
          }

          std::make_shared<session>(std::move(socket), total_nodes)->start(dealing_bytes);
          do_accept();
        }
      });

  }

  tcp::acceptor acceptor_;
  protobuff_ser::Dealing dealing_bytes;
  unsigned int total_nodes;
  std::atomic<bool> is_first_connection;
};


class client {
public:
    client(const std::string& serverAddress, const std::string& serverPort, const unsigned long total_nodes,  const unsigned long threshold)
        : io_context_(), socket_(io_context_), serverAddress_(serverAddress), serverPort_(serverPort), total_nodes(total_nodes), threshold(threshold)
    {
    }

    void run()
    {
        try {
            connectToServer();
            receiveDealing();
        } catch (const std::exception& ex) {
            std::cerr << "Exception: " << ex.what() << std::endl;
        }
    }

private:
    void connectToServer()
    {
        tcp::resolver resolver(io_context_);
        boost::asio::connect(socket_, resolver.resolve(serverAddress_, serverPort_));
    }

    void receiveDealing()
    {
        boost::asio::streambuf receive_buffer;
        const std::string delimiter = "\r\n\r\n";
        boost::system::error_code error;

        boost::asio::read_until(socket_, receive_buffer, delimiter, error);
        if (!error) {
            DKG_Helper dkg_helper(total_nodes, threshold);

            std::string dealing_str(boost::asio::buffers_begin(receive_buffer.data()),
                                    boost::asio::buffers_end(receive_buffer.data()) - delimiter.size());

            //std::cout << "Received Dealing object from the server" << std::endl;
            protobuff_ser::Dealing dealing_bytes;
            dealing_bytes.ParseFromString(dealing_str);

            bool flag = dkg_helper.verify_dealing(dealing_bytes);

            if (flag) {
                boost::asio::write(socket_, boost::asio::buffer("Ack" + delimiter));
                socket_.close();
                std::cout << "Dealing verified!" << std::endl;
            }
        } else {
            std::cerr << "Error receiving data: " << error.message() << std::endl;
        }
    }

    boost::asio::io_context io_context_;
    tcp::socket socket_;
    std::string serverAddress_;
    std::string serverPort_;
    unsigned long total_nodes;
    unsigned long threshold;
      
};




