import matplotlib.pyplot as plt

def generate_graph(name, name2, linebreak):
    try:
        fp = open(name, "r")

        lines = fp.readlines()
        fp.close()
        x = []  # time
        y = []  # num of packets
        timer = 0
        counter = 0
        for line in lines:
            counter += 1
            if counter == (len(lines)-linebreak):
                break
            spliter = line.split(" ")
            timer += float(spliter[1])
            x.append(timer)
            y.append(spliter[0])
            

        fig, ax = plt.subplots()
        ax.plot(x, y)

        ax.set(xlabel="time needed to send packet in miliseconds.", ylabel="number of packets sent.",
            title="packet sending time vs number of packets sent.")
            
        # Make the y axis as logarithmic scale
        ax.set_yscale('log')
        	
        fig.savefig(name2)
    
    except Exception as e:
        print("Error while generating graph for " + name)
        print("Make sure you have the file " + name + " in the same directory as this script.")
        print("Python interpreter threw exception:")
        print(e)
        return

    
    #plt.show()

if __name__ == "__main__":

    print("Generating graphs...")

    print("Generating graphs for the attack...")
    generate_graph("syns_results_c.txt", "Syn_pkts_c.png", 2)
    generate_graph("syns_results_p.txt", "Syn_pkts_p.png", 2)

    print("Generating graphs for the pings...")
    generate_graph("pings_results_c.txt", "Pings_c.png", 1)
    generate_graph("pings_results_p.txt", "Pings_p.png", 1)

    print("Done!")
