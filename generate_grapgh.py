import matplotlib.pyplot as plt
def generate_graph(name, name2):
    fp = open(name, "r")
    lines = fp.readlines()
    fp.close()
    x = []  # time
    y = []  # num of packets
    timer = 0
    counter = 0
    for line in lines:
        if counter == (len(lines)-2):
            break
        spliter = line.split(" ")
        timer += float(spliter[1])
        x.append(timer)
        y.append(spliter[0])
        counter = counter + 1

    fig, ax = plt.subplots()
    ax.plot(x, y)

    ax.set(xlabel="time needed to send packet in miliseconds.", ylabel="number of packets sent.",
           title="packet sending time vs number of packets sent.")
    ax.set_yscale('log')
    fig.savefig(name2)
    plt.show()

if __name__ == "__main__":
    generate_graph("syns_results_p.txt", "Syn_pkts_p.png")
    generate_graph("syns_results_c.txt", "Syn_pkts_c.png")