#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <iomanip>
#include <atomic>
#include <thread>
#include <vector>
#include <cstdint>
#include <fstream> 

std::vector<unsigned char> shake128_hash(const std::string& input, size_t output_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* shake = EVP_shake128();
    std::vector<unsigned char> output(output_len);
    
    EVP_DigestInit_ex(ctx, shake, nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    EVP_DigestFinalXOF(ctx, output.data(), output_len);
    
    EVP_MD_CTX_free(ctx);
    return output;
}

// Função para converter hash para string hexadecimal
std::string hash_to_hex(const std::vector<unsigned char>& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : hash) {
        ss << std::setw(2) << (int)b;
    }
    return ss.str();
}

int main() {
    // String alvo com 'Á' codificado em UTF-8 (C3 81)
    std::string target_str = "Aluno: \xC3\x81lisson Rodrigues";
    size_t output_len = 4;
    
    // Calcula hash alvo
    auto target_hash = shake128_hash(target_str, output_len);
    std::string target_hex = hash_to_hex(target_hash);
    
    std::cout << "Hash alvo (hex): " << target_hex << std::endl;
    
    // Salva informações iniciais no arquivo
    std::ofstream result_file("desafio_b.txt");
    if (!result_file.is_open()) {
        std::cerr << "Erro ao abrir arquivo desafio_b.txt para escrita!" << std::endl;
        return 1;
    }
    
    result_file << "===== RESULTADO DO DESAFIO B =====\n";
    result_file << "Aluno: Álisson Rodrigues\n";
    result_file << "String original (x1): \"" << target_str << "\"\n";
    result_file << "Hash alvo (4 bytes): " << target_hex << "\n\n";
    
    const int num_threads = std::thread::hardware_concurrency();
    std::cout << "Usando " << num_threads << " threads." << std::endl;
    result_file << "Threads utilizadas: " << num_threads << "\n";
    
    std::atomic<bool> found(false);
    std::string collision_str;
    std::vector<unsigned char> collision_hash;
    
    // Função executada por cada thread
    auto worker = [&](int thread_id) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        const EVP_MD* shake = EVP_shake128();
        std::vector<unsigned char> candidate_hash(output_len);
        uint64_t counter = thread_id;
        std::string candidate;
        
        while (!found) {
            candidate = std::to_string(counter);
            EVP_DigestInit_ex(ctx, shake, nullptr);
            EVP_DigestUpdate(ctx, candidate.c_str(), candidate.size());
            EVP_DigestFinalXOF(ctx, candidate_hash.data(), output_len);
            
            if (candidate_hash == target_hash && candidate != target_str) {
                found = true;
                collision_str = candidate;
                collision_hash = candidate_hash;
                break;
            }
            counter += num_threads;
        }
        EVP_MD_CTX_free(ctx);
    };
    
    // Inicia threads
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, i);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Resultado
    if (found) {
        std::string collision_hex = hash_to_hex(collision_hash);
        
        std::cout << "\nCOLISÃO ENCONTRADA!\n";
        std::cout << "String original: \"" << target_str << "\"\n";
        std::cout << "Nova string (x2): \"" << collision_str << "\"\n";
        std::cout << "Hash de x2 (hex): " << collision_hex << std::endl;
        
        // Salva resultado no arquivo
        result_file << "STATUS: SUCESSO\n";
        result_file << "String colidida (x2): \"" << collision_str << "\"\n";
        result_file << "Hash da colisão: " << collision_hex << "\n";
        result_file << "\nOBSERVACOES:\n";
        result_file << "- Este resultado foi gerado automaticamente pelo programa\n";
        result_file << "- A colisao ocorre apenas nos primeiros 4 bytes do hash\n";
        result_file << "- Em sistemas reais, hashes devem ter tamanho minimo de 256 bits\n";
    } else {
        std::cout << "Nenhuma colisão encontrada.\n";
        result_file << "STATUS: FALHA\n";
        result_file << "Nenhuma colisao encontrada apos busca exaustiva.\n";
    }
    
    result_file.close();
    std::cout << "\nResultado salvo em: desafio_b.txt" << std::endl;
    
    return 0;
}
