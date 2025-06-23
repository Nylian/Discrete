import os
os.system('cls')


def addition (number1, number2, number_base):
    if(number_base == "1"):
     
        convertedTo_decimalSum = int(number1, 2) + int(number2, 2)
        Final = bin(int(convertedTo_decimalSum))[2:]
        
        
    elif(number_base == "2"):
    
        convertedTo_decimalSum = int(number1, 8) + int(number2, 8)
        Final = oct(int(convertedTo_decimalSum))[2:]
        
    elif(number_base == "3"):
        
        convertedTo_decimalSum = int(number1, 16) + int(number2, 16)
        Final = hex(int(convertedTo_decimalSum))[2:]
        
    else:
        print("Try again")
        
    return Final
        
        
def subtraction (number1, number2, number_base):
    if(number_base == "1"):
     
        convertedTo_decimalSum = int(number1, 2) - int(number2, 2)
        Final = bin(int(convertedTo_decimalSum))[2:]
        
        
    elif(number_base == "2"):
    
        convertedTo_decimalSum = int(number1, 8) - int(number2, 8)
        Final = oct(int(convertedTo_decimalSum))[2:]
        
    elif(number_base == "3"):
        
        convertedTo_decimalSum = int(number1, 16) - int(number2, 16)
        Final = hex(int(convertedTo_decimalSum))[2:]
        
    else:
        print("Try again")
        
    return Final
    
def multiplication (number1, number2, number_base):
    if(number_base == "1"):
     
        convertedTo_decimalSum = int(number1, 2) * int(number2, 2)
        Final = bin(int(convertedTo_decimalSum))[2:]
        
        
    elif(number_base == "2"):
    
        convertedTo_decimalSum = int(number1, 8) * int(number2, 8)
        Final = oct(int(convertedTo_decimalSum))[2:]
        
    elif(number_base == "3"):
        
        convertedTo_decimalSum = int(number1, 16) * int(number2, 16)
        Final = hex(int(convertedTo_decimalSum))[2:]
        
    else:
        print("Try again")
        
    return Final


def division (number1, number2, number_base):
    
    if(number1 == "0" or number2 == "0"): return "Cannot divide 0"
    if(number_base == "1"):
     
        convertedTo_decimalSum = int(number1, 2) / int(number2, 2)
        Final = bin(int(convertedTo_decimalSum))[2:]
        
        
    elif(number_base == "2"):
    
        convertedTo_decimalSum = int(number1, 8) / int(number2, 8)
        Final = oct(int(convertedTo_decimalSum))[2:]
        
    elif(number_base == "3"):
        
        convertedTo_decimalSum = int(number1, 16) / int(number2, 16)
        Final = hex(int(convertedTo_decimalSum))[2:]
        
    else:
        print("Try again")
        
    return Final
    
running = True

while(running):
    os.system("cls")
    numeric_base = ["Binary", "Octal", "Hexadecimal"]
    print("This program lets you choose what arithmetic operation \nand numeric base you want to use.  \n1. Binary \n2. Octal \n3. Hexadecimal")
    chosen_numerbase = input("Choose what numeric base you want to use: ")
    

    os.system('cls')
    print("Choose which operation do you want to use in \"" + numeric_base[int(chosen_numerbase) - 1] + "\"\n1. Addition \n2. Subtraction \n3. Multiplication \n4. Division")

    operation = input("Operation: ")
    os.system('cls')

    first_input = input("Input first " + numeric_base[int(chosen_numerbase) - 1] + " number: ")
    second_input = input("Input Second " + numeric_base[int(chosen_numerbase) - 1] + " number: ")

    match operation:
        
        case "1":
            result = addition(first_input, second_input, chosen_numerbase)
            print("Sum: " + result)
        case "2":
            result = subtraction(first_input, second_input, chosen_numerbase)
            print("Difference: " + result)
        case "3":
            result = multiplication(first_input, second_input, chosen_numerbase)
            print("Product: " + result)
        case "4":
            result = division(first_input, second_input, chosen_numerbase)
            print("Quotient: " + result)
            
        case _:
            print("invalid operator")
    
    i = input("Start again [y/n]")
    if i == "n" or i == "N": running = False
    

os.system("cls")
print("Program closed")
        
        
