from z3 import Solver, Z3Exception, parse_smt2_string, BoolRef, Implies, And, Not, unsat
import sys

def check_consistency(smt_file1_path, smt_file2_path):
    try:
        with open(smt_file1_path, 'r') as f1:
            smt_content1 = f1.read()
        with open(smt_file2_path, 'r') as f2:
            smt_content2 = f2.read()

        s = Solver()
        parsed_smt1 = parse_smt2_string(smt_content1)
        parsed_smt2 = parse_smt2_string(smt_content2)

        if not parsed_smt1 or not parsed_smt1.assertions():
            return False, "Error: SMT parsing failed or no assertions found for file 1."
        if not parsed_smt2 or not parsed_smt2.assertions():
            return False, "Error: SMT parsing failed or no assertions found for file 2."

        f1 = And(parsed_smt1.assertions())
        f2 = And(parsed_smt2.assertions())


        if not isinstance(f1, BoolRef):
            return False, "Error: Expected boolean formula in SMT file 1."
        if not isinstance(f2, BoolRef):
            return False, "Error: Expected boolean formula in SMT file 2."


        s.add(Not(And(Implies(f1, f2), Implies(f2, f1)))) # Check if negation of mutual implication is unsatisfiable

        if s.check() == unsat:
            return True, "Consistent: The two SMT formulas are equivalent."
        else:
            return False, "Inconsistent: The two SMT formulas are not equivalent."

    except Z3Exception as e:
        return False, f"Z3 Solver Error: {e}"
    except Exception as e:
        return False, f"General Error during consistency check: {e}"

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python main.py <smt_file1_path> <smt_file2_path>")
        sys.exit(1)

    smt_file1_path = sys.argv[1]
    smt_file2_path = sys.argv[2]

    is_consistent, result_message = check_consistency(smt_file1_path, smt_file2_path)

    if is_consistent:
        print("Consistent")
    else:
        print("Inconsistent")
    print(result_message)
